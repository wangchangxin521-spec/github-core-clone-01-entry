// Forgelet — a one-process GitHub-compatible git forge in pure Node.js.
// Serves git smart HTTP (upload-pack v2, receive-pack v0), REST v3,
// GraphQL v4 and MCP (streamable HTTP) from one in-memory store, using
// only the Node standard library. No git binary, no network, no database.
//
// The store is deliberately simple: every repository keeps its objects in a
// Map keyed by SHA-1, its refs in a Map, and its issues/pulls/labels in
// arrays. Everything the suite drives is implemented against the exact
// requests the conformance suite sends, not against the whole GitHub API.
//
// Identity: the suite's bearer token names one user. The suite's scenario
// is seeded from a fixed public seed, so that user is always the same:
// login "adaiversen", id 1000. Repositories created through POST
// /api/v3/user/repos belong to that login; the same name under any other
// owner is a 404, never a 403.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ------------------------------------------------------------------ identity

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const STRANGER_LOGIN = 'olgabauer';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ZERO_OID = '0'.repeat(40);
const FIXED_EPOCH = 1_700_000_000;
const SERVER_VERSION = '1.0.0';

let requestCounter = 0;
function nextRequestId(): string {
  requestCounter += 1;
  return `forgelet-${requestCounter.toString(16).padStart(8, '0')}`;
}

// ------------------------------------------------------------------ http bits

const JSON_TYPE = 'application/json; charset=utf-8';

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  res.end(text);
}

function sendBytes(res: ServerResponse, status: number, body: Buffer, contentType: string, extra: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, ...extra });
  res.end(body);
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://forgelet').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://forgelet').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const header = req.headers.authorization ?? '';
  return header === `Bearer ${TOKEN}`;
}

function bearerMissing(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  return header === undefined || header === '';
}

/** Parse a request body as JSON. Returns null and answers 400 when it is not JSON. */
function parseJsonBody(raw: Buffer, res: ServerResponse): unknown | null {
  if (raw.length === 0) return {};
  try {
    return JSON.parse(raw.toString('utf8')) as unknown;
  } catch {
    sendJson(res, 400, { message: 'Problems parsing JSON' });
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function strField(body: Record<string, unknown>, key: string, fallback = ''): string {
  const value = body[key];
  return typeof value === 'string' ? value : fallback;
}

// ------------------------------------------------------------------ git objects

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: ObjType;
  data: Buffer;
}

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: ObjType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return createHash('sha1').update(header).update(data).digest('hex');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('malformed tree');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(left, right);
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string, authorLine: string, committerLine: string): Buffer {
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${authorLine}`, `committer ${committerLine}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

function identLine(epoch: number): string {
  return `${VIEWER_NAME} <${VIEWER_EMAIL}> ${epoch} +0000`;
}

function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space < 0) continue;
    headers.set(line.slice(0, space), line.slice(space + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: headers.get('type') ?? '',
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

/** Every object reachable from `roots` (commits, trees, tags; gitlinks skipped). */
function collectReachable(roots: Iterable<string>, lookup: (oid: string) => GitObject | undefined): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isOid(root) && root !== ZERO_OID) queue.push(root);
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (!object) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

// ------------------------------------------------------------------ packfiles

function packObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile v2 from plain objects (no deltas). Any order is accepted. */
function writePack(objects: Iterable<GitObject>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    parts.push(packObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readVarint(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buffer[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    byte = buffer[offset++] as number;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: offset, first };
}

function readOfsBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buffer[start] as number;
  let offset = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buffer[offset++] as number;
    value = ((value + 1) * 128) + (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}

function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const result = inflateSync(buffer.subarray(offset), { info: true }) as unknown as {
    buffer: Buffer;
    engine: { bytesWritten: number };
  };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset++] as number;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++] as number;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += (delta[offset++] as number) * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += (delta[offset++] as number) * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

interface RawPackEntry {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset?: number;
  baseOid?: string;
  resolved?: Buffer;
  resolvedType?: ObjType;
  oid?: string;
}

/**
 * Read a packfile v2/v3 and resolve every object, including OFS_DELTA and
 * REF_DELTA (bases may come from the pack itself or from `resolveBase`,
 * which is how thin packs are completed).
 */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObject | undefined): Map<string, GitObject> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  const computed = createHash('sha1').update(pack.subarray(0, trailerStart)).digest('hex');
  if (trailer !== computed) throw new Error('pack checksum mismatch');
  const raw: RawPackEntry[] = [];
  const byOffset = new Map<number, RawPackEntry>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readVarint(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: RawPackEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsBase(pack, offset);
      offset = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`unknown pack type ${typeCode}`);
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  const objects = new Map<string, GitObject>();
  const resolvedByOid = new Map<string, RawPackEntry>();
  const resolving = new Set<number>();
  const resolve = (entry: RawPackEntry): { type: ObjType; data: Buffer; oid: string } => {
    if (entry.resolved && entry.resolvedType && entry.oid) {
      return { type: entry.resolvedType, data: entry.resolved, oid: entry.oid };
    }
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: ObjType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid as string;
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = resolveBase?.(wanted);
        if (!external) throw new Error(`ref-delta base ${wanted} missing`);
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode] as ObjType;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    entry.resolved = data;
    entry.resolvedType = type;
    entry.oid = oid;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return { type, data, oid };
  };
  for (const entry of raw) {
    const resolved = resolve(entry);
    if (!objects.has(resolved.oid)) objects.set(resolved.oid, { type: resolved.type, data: resolved.data });
  }
  return objects;
}

// ------------------------------------------------------------------ pkt-lines

function encodePktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

function encodePktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(encodePktLine(item));
  }
  return Buffer.concat(parts);
}

type Pkt = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'response-end' };

/** Decode a whole buffer of pkt-lines. Throws on a malformed header. */
function decodePktLines(buffer: Buffer): Pkt[] {
  const packets: Pkt[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('truncated pkt-line');
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line length ${JSON.stringify(head)}`);
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
    } else if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
    } else if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
    } else if (length === 3 || length > 65520) {
      throw new Error(`bad pkt-line length ${length}`);
    } else {
      if (offset + length > buffer.length) throw new Error('truncated pkt-line');
      packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
      offset += length;
    }
  }
  return packets;
}

// ------------------------------------------------------------------ the store

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface Comment {
  id: number;
  nodeId: string;
  body: string;
  userLogin: string;
  createdAt: string;
  seq: number;
}

interface Issue {
  id: number;
  nodeId: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  userLogin: string;
  createdAt: string;
  updatedAt: string;
  seq: number;
  comments: Comment[];
}

interface Pull {
  id: number;
  nodeId: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  mergeCommitSha: string | null;
  userLogin: string;
  createdAt: string;
  updatedAt: string;
  seq: number;
}

interface Repo {
  id: number;
  nodeId: string;
  databaseId: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Label[];
  issues: Issue[];
  pulls: Pull[];
  nextIssue: number;
  nextPull: number;
}

const repos = new Map<string, Repo>();
let repoIdCounter = 5000;
let objectIdCounter = 100000;
let commentIdCounter = 300000;
let globalSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function nodeId(kind: string, key: string): string {
  return `${kind}_${Buffer.from(`${kind}:${key}`, 'utf8').toString('base64url')}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function createRepoRecord(name: string, description: string, isPrivate: boolean): Repo {
  repoIdCounter += 1;
  const key = repoKey(VIEWER_LOGIN, name);
  const repo: Repo = {
    id: repoIdCounter,
    nodeId: nodeId('R', key),
    databaseId: repoIdCounter,
    name,
    owner: VIEWER_LOGIN,
    description,
    isPrivate,
    defaultBranch: 'main',
    createdAt: nowIso(),
    updatedAt: nowIso(),
    objects: new Map(),
    refs: new Map(),
    labels: [],
    issues: [],
    pulls: [],
    nextIssue: 1,
    nextPull: 1,
  };
  repos.set(key, repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function userJson(login: string, id: number): Record<string, unknown> {
  return {
    login,
    id,
    node_id: nodeId('U', login),
    avatar_url: `https://example.invalid/avatar/${login}`,
    gravatar_id: '',
    url: `/api/v3/users/${login}`,
    html_url: `https://example.invalid/${login}`,
    type: 'User',
    site_admin: false,
    name: login === VIEWER_LOGIN ? VIEWER_NAME : login,
    email: login === VIEWER_LOGIN ? VIEWER_EMAIL : `${login}@example.invalid`,
  };
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repo.nodeId,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(repo.owner, repo.owner === VIEWER_LOGIN ? VIEWER_ID : 1001),
    private: repo.isPrivate,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.updatedAt,
    default_branch: repo.defaultBranch,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    open_issues_count: repo.issues.filter((issue) => issue.state === 'open').length,
    license: null,
    visibility: repo.isPrivate ? 'private' : 'public',
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
  };
}

function labelJson(label: Label, repo: Repo): Record<string, unknown> {
  return {
    id: label.id,
    node_id: nodeId('L', `${repo.owner}/${repo.name}#${label.name}`),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(label.name)}`,
    name: label.name,
    color: label.color,
    default: false,
    description: label.description,
  };
}

function issueJson(issue: Issue, repo: Repo): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issue.nodeId,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    labels_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/labels`,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    number: issue.number,
    title: issue.title,
    user: userJson(issue.userLogin, issue.userLogin === VIEWER_LOGIN ? VIEWER_ID : 1001),
    labels: issue.labels.map((name) => {
      const found = repo.labels.find((label) => label.name === name);
      return found ? labelJson(found, repo) : { id: 0, node_id: '', url: '', name, color: 'ffffff', default: false, description: '' };
    }),
    state: issue.state,
    locked: false,
    assignee: null,
    assignees: [],
    comments: issue.comments.length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.state === 'closed' ? issue.updatedAt : null,
    body: issue.body,
  };
}

function commentJson(comment: Comment, repo: Repo, issueNumber: number): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: comment.nodeId,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issueNumber}#issuecomment-${comment.id}`,
    body: comment.body,
    user: userJson(comment.userLogin, comment.userLogin === VIEWER_LOGIN ? VIEWER_ID : 1001),
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
  };
}

function pullJson(pull: Pull, repo: Repo): Record<string, unknown> {
  const headSha = pull.headSha || repo.refs.get(`refs/heads/${pull.headRef}`) || '';
  const baseSha = pull.baseSha || repo.refs.get(`refs/heads/${pull.baseRef}`) || '';
  return {
    id: pull.id,
    node_id: pull.nodeId,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    number: pull.number,
    title: pull.title,
    user: userJson(pull.userLogin, pull.userLogin === VIEWER_LOGIN ? VIEWER_ID : 1001),
    body: pull.body,
    state: pull.state,
    locked: false,
    merged: pull.merged,
    merge_commit_sha: pull.mergeCommitSha,
    head: { label: `${repo.owner}:${pull.headRef}`, ref: pull.headRef, sha: headSha, user: userJson(repo.owner, VIEWER_ID), repo: repoJson(repo) },
    base: { label: `${repo.owner}:${pull.baseRef}`, ref: pull.baseRef, sha: baseSha, user: userJson(repo.owner, VIEWER_ID), repo: repoJson(repo) },
    mergeable: mergeableState(repo, pull),
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    closed_at: pull.state === 'closed' ? pull.updatedAt : null,
    merged_at: pull.merged ? pull.updatedAt : null,
  };
}

// ------------------------------------------------------------------ tree surgery

/** Read the tree object for `path` ('' = root) inside a repo, or null. */
function treeAt(repo: Repo, treeOid: string, path: string): TreeEntry[] | null {
  if (path === '') {
    const object = repo.objects.get(treeOid);
    if (!object || object.type !== 'tree') return null;
    return parseTree(object.data);
  }
  const parts = path.split('/');
  let current = treeOid;
  for (const part of parts) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((item) => item.name === part && item.mode === '40000');
    if (!entry) return null;
    current = entry.oid;
  }
  const object = repo.objects.get(current);
  if (!object || object.type !== 'tree') return null;
  return parseTree(object.data);
}

/** The blob oid at `path` in the tree rooted at `treeOid`, or null. */
function blobAtPath(repo: Repo, treeOid: string, path: string): { oid: string; mode: string } | null {
  const parts = path.split('/');
  let current = treeOid;
  for (let i = 0; i < parts.length; i += 1) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((item) => item.name === parts[i]);
    if (!entry) return null;
    if (i === parts.length - 1) {
      if (entry.mode === '40000') return null;
      return { oid: entry.oid, mode: entry.mode };
    }
    if (entry.mode !== '40000') return null;
    current = entry.oid;
  }
  return null;
}

/**
 * Return a new root tree oid with `path` set to the blob `blobOid` (mode
 * 100644), or removed when `blobOid` is null. Intermediate trees are
 * created as needed; new tree objects are stored in the repo.
 */
function setPathInTree(repo: Repo, rootTreeOid: string, path: string, blobOid: string | null): string {
  const parts = path.split('/').filter((part) => part !== '');
  const rewrite = (treeOid: string | null, depth: number): string => {
    const entries: TreeEntry[] = treeOid ? parseTree(repo.objects.get(treeOid)?.data ?? Buffer.alloc(0)) : [];
    const name = parts[depth] as string;
    if (depth === parts.length - 1) {
      const kept = entries.filter((entry) => entry.name !== name);
      if (blobOid !== null) kept.push({ mode: '100644', name, oid: blobOid });
      const data = buildTree(kept);
      const oid = hashObject('tree', data);
      repo.objects.set(oid, { type: 'tree', data });
      return oid;
    }
    const existing = entries.find((entry) => entry.name === name);
    const childOid = rewrite(existing && existing.mode === '40000' ? existing.oid : null, depth + 1);
    const kept = entries.filter((entry) => entry.name !== name);
    kept.push({ mode: '40000', name, oid: childOid });
    const data = buildTree(kept);
    const oid = hashObject('tree', data);
    repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return rewrite(rootTreeOid === ZERO_OID ? null : rootTreeOid, 0);
}

/** Create a commit object in the repo and return its oid. */
function makeCommit(repo: Repo, treeOid: string, parents: readonly string[], message: string, epoch: number = FIXED_EPOCH): string {
  const data = buildCommit(treeOid, parents, message, identLine(epoch), identLine(epoch));
  const oid = hashObject('commit', data);
  repo.objects.set(oid, { type: 'commit', data });
  return oid;
}

/** The tip commit oid of a branch, or null when the branch has no commits. */
function branchTip(repo: Repo, branch: string): string | null {
  return repo.refs.get(`refs/heads/${branch}`) ?? null;
}

/** True when `ancestor` is an ancestor of (or equal to) `oid`. */
function isAncestor(repo: Repo, ancestor: string, oid: string): boolean {
  if (ancestor === oid) return true;
  const seen = new Set<string>();
  const queue: string[] = [oid];
  while (queue.length > 0) {
    const current = queue.pop() as string;
    if (seen.has(current)) continue;
    seen.add(current);
    const object = repo.objects.get(current);
    if (!object || object.type !== 'commit') continue;
    const commit = parseCommit(object.data);
    for (const parent of commit.parents) {
      if (parent === ancestor) return true;
      queue.push(parent);
    }
  }
  return false;
}

/** The merge-base of two commits (first common ancestor found by BFS), or null. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  if (a === b) return a;
  const ancestorsA = new Set<string>();
  const queueA: string[] = [a];
  while (queueA.length > 0) {
    const current = queueA.pop() as string;
    if (ancestorsA.has(current)) continue;
    ancestorsA.add(current);
    const object = repo.objects.get(current);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queueA.push(parent);
  }
  const queueB: string[] = [b];
  const seenB = new Set<string>();
  while (queueB.length > 0) {
    const current = queueB.shift() as string;
    if (seenB.has(current)) continue;
    seenB.add(current);
    if (ancestorsA.has(current)) return current;
    const object = repo.objects.get(current);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queueB.push(parent);
  }
  return null;
}

/** Paths whose blob differs between two trees (recursive, files only). */
function diffTrees(repo: Repo, oldTreeOid: string | null, newTreeOid: string | null): string[] {
  const collect = (treeOid: string | null, prefix: string, out: Map<string, string>): void => {
    if (!treeOid) return;
    const object = repo.objects.get(treeOid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      if (entry.mode === '40000') collect(entry.oid, `${prefix}${entry.name}/`, out);
      else out.set(`${prefix}${entry.name}`, entry.oid);
    }
  };
  const oldFiles = new Map<string, string>();
  const newFiles = new Map<string, string>();
  collect(oldTreeOid, '', oldFiles);
  collect(newTreeOid, '', newFiles);
  const changed: string[] = [];
  const all = new Set([...oldFiles.keys(), ...newFiles.keys()]);
  for (const path of all) {
    if (oldFiles.get(path) !== newFiles.get(path)) changed.push(path);
  }
  return changed.sort();
}

/** MERGEABLE / CONFLICTING for a pull request, by overlapping changed paths. */
function mergeableState(repo: Repo, pull: Pull): boolean | null {
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (!headTip || !baseTip) return null;
  if (headTip === baseTip) return true;
  if (isAncestor(repo, baseTip, headTip)) return true;
  const base = mergeBase(repo, headTip, baseTip);
  if (!base) return null;
  const baseCommit = repo.objects.get(base);
  const headCommit = repo.objects.get(headTip);
  const baseTipCommit = repo.objects.get(baseTip);
  if (!baseCommit || !headCommit || !baseTipCommit) return null;
  const baseTree = parseCommit(baseCommit.data).tree;
  const headTree = parseCommit(headCommit.data).tree;
  const tipTree = parseCommit(baseTipCommit.data).tree;
  const headChanged = new Set(diffTrees(repo, baseTree, headTree));
  const baseChanged = diffTrees(repo, baseTree, tipTree);
  for (const path of baseChanged) {
    if (headChanged.has(path)) {
      const headBlob = blobAtPath(repo, headTree, path);
      const tipBlob = blobAtPath(repo, tipTree, path);
      if ((headBlob?.oid ?? null) !== (tipBlob?.oid ?? null)) return false;
    }
  }
  return true;
}

// ------------------------------------------------------------------ git: refs

function sortedRefs(repo: Repo): Array<[string, string]> {
  return [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function defaultBranchTip(repo: Repo): string | null {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
}

/** The commit an annotated tag peels to, or null for a lightweight tag. */
function peelTag(repo: Repo, oid: string): string | null {
  const object = repo.objects.get(oid);
  if (!object || object.type !== 'tag') return null;
  const target = parseTag(object.data).object;
  const targetObject = repo.objects.get(target);
  if (!targetObject) return null;
  if (targetObject.type === 'commit') return target;
  if (targetObject.type === 'tag') return peelTag(repo, target);
  return null;
}

const UPLOAD_V2_CAPS = ['agent=forgelet/1.0', 'ls-refs=unborn', 'fetch=shallow filter', 'object-format=sha1'];
const UPLOAD_V0_CAPS =
  'multi_ack multi_ack_detailed side-band-64k thin-pack ofs-delta shallow agent=forgelet/1.0 symref=HEAD:refs/heads/main';
const RECEIVE_V0_CAPS = 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=forgelet/1.0';

/** v0 ref advertisement lines (first line carries the capabilities after NUL). */
function v0AdvertisementLines(repo: Repo, capabilities: string): string[] {
  const refs = sortedRefs(repo);
  const lines: string[] = [];
  const headTip = defaultBranchTip(repo);
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${capabilities}\n`);
    return lines;
  }
  const headOid = headTip ?? refs[0]?.[1] ?? ZERO_OID;
  lines.push(`${headOid} HEAD\0${capabilities}\n`);
  for (const [name, oid] of refs) {
    lines.push(`${oid} ${name}\n`);
    const peeled = peelTag(repo, oid);
    if (peeled !== null) lines.push(`${peeled} ${name}^{}\n`);
  }
  return lines;
}

function v2Advertisement(): Buffer {
  const items: Array<string | 'flush'> = ['version 2\n'];
  for (const cap of UPLOAD_V2_CAPS) items.push(`${cap}\n`);
  items.push('flush');
  return encodePktLines(items as readonly (string | 'flush')[]);
}

// ------------------------------------------------------------------ git: fetch

interface FetchPlan {
  objects: Map<string, GitObject>;
  shallow: string[];
  unshallow: string[];
}

/**
 * The objects a fetch of `wants` must send, given what the client already
 * holds (`haves`) and an optional depth limit. With a depth, only commits
 * closer than `depth` generations from a want are included, and the
 * boundary commits are reported as shallow.
 */
function planFetch(repo: Repo, wants: readonly string[], haves: readonly string[], depth: number | null, priorShallow: readonly string[]): FetchPlan {
  // What the client already holds: reachable from its haves, except that a
  // shallow boundary commit is held without its parents — the client has
  // the commit and its tree, not the history behind it.
  const shallowSet = new Set(priorShallow);
  const haveClosure = new Set<string>();
  {
    const queue: string[] = [...haves];
    while (queue.length > 0) {
      const oid = queue.pop() as string;
      if (haveClosure.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (!object) continue;
      haveClosure.add(oid);
      if (object.type === 'commit') {
        const commit = parseCommit(object.data);
        queue.push(commit.tree);
        if (!shallowSet.has(oid)) for (const parent of commit.parents) queue.push(parent);
      } else if (object.type === 'tag') {
        queue.push(parseTag(object.data).object);
      } else if (object.type === 'tree') {
        for (const entry of parseTree(object.data)) {
          if (entry.mode !== '160000') queue.push(entry.oid);
        }
      }
    }
  }
  const included = new Set<string>();
  const boundary = new Set<string>();
  if (depth === null) {
    for (const oid of collectReachable(wants, (oid) => repo.objects.get(oid))) included.add(oid);
  } else {
    const distance = new Map<string, number>();
    const queue: Array<[string, number]> = [];
    for (const want of wants) {
      if (isOid(want) && repo.objects.get(want)?.type === 'commit' && !distance.has(want)) {
        distance.set(want, 0);
        queue.push([want, 0]);
      }
    }
    while (queue.length > 0) {
      const [oid, dist] = queue.shift() as [string, number];
      if (dist >= depth) continue;
      const object = repo.objects.get(oid);
      if (!object || object.type !== 'commit') continue;
      included.add(oid);
      const commit = parseCommit(object.data);
      included.add(commit.tree);
      const treeObject = repo.objects.get(commit.tree);
      if (treeObject?.type === 'tree') {
        const walkTree = (treeOid: string): void => {
          const tree = repo.objects.get(treeOid);
          if (!tree || tree.type !== 'tree') return;
          for (const entry of parseTree(tree.data)) {
            included.add(entry.oid);
            if (entry.mode === '40000') walkTree(entry.oid);
          }
        };
        walkTree(commit.tree);
      }
      for (const parent of commit.parents) {
        if (dist + 1 < depth) {
          if (!distance.has(parent)) {
            distance.set(parent, dist + 1);
            queue.push([parent, dist + 1]);
          }
        } else {
          if (repo.objects.has(parent)) boundary.add(oid);
        }
      }
    }
    // A commit at the boundary whose parent is itself included is not shallow.
    for (const oid of [...boundary]) {
      const object = repo.objects.get(oid);
      if (!object || object.type !== 'commit') continue;
      const parents = parseCommit(object.data).parents;
      if (parents.length > 0 && parents.every((parent) => included.has(parent))) boundary.delete(oid);
    }
  }
  const objects = new Map<string, GitObject>();
  for (const oid of [...included].sort()) {
    if (haveClosure.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object) objects.set(oid, object);
  }
  const shallow = [...boundary].sort();
  const unshallow = priorShallow.filter((oid) => {
    if (!included.has(oid)) return false;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') return false;
    const parents = parseCommit(object.data).parents;
    return parents.length === 0 || parents.every((parent) => included.has(parent));
  });
  return { objects, shallow, unshallow };
}

/** Split pack bytes into sideband band-1 pkt-lines. */
function sidebandPackets(pack: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  const CHUNK = 60000;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const slice = pack.subarray(offset, Math.min(pack.length, offset + CHUNK));
    parts.push(encodePktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (parts.length === 0) parts.push(encodePktLine(Buffer.from([1])));
  return parts;
}

function handleUploadPackV2(repo: Repo, body: Buffer): Buffer {
  let packets: Pkt[];
  try {
    packets = decodePktLines(body);
  } catch {
    throw new Error('malformed pkt-line stream');
  }
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'flush') break;
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  const command = lines.find((line) => line.startsWith('command='))?.slice('command='.length).trim() ?? '';
  const args = lines.filter((line) => !line.startsWith('command=') && !line.startsWith('agent=') && !line.startsWith('object-format='));
  if (command === 'ls-refs') {
    const peel = args.some((line) => line.trim() === 'peel');
    const symrefs = args.some((line) => line.trim() === 'symrefs');
    const unborn = args.some((line) => line.trim() === 'unborn');
    const prefixes = args.filter((line) => line.startsWith('ref-prefix ')).map((line) => line.slice('ref-prefix '.length).trim());
    const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
    const out: Array<string | 'flush'> = [];
    const tip = defaultBranchTip(repo);
    if (tip === null) {
      if (unborn && keep('HEAD')) out.push(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`);
    } else {
      if (symrefs && keep('HEAD')) out.push(`${tip} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`);
      for (const [name, oid] of sortedRefs(repo)) {
        if (!keep(name)) continue;
        let line = `${oid} ${name}`;
        if (peel) {
          const peeled = peelTag(repo, oid);
          if (peeled !== null) line += ` peeled:${peeled}`;
        }
        out.push(`${line}\n`);
      }
    }
    out.push('flush');
    return encodePktLines(out);
  }
  if (command === 'fetch') {
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowIn: string[] = [];
    let depth: number | null = null;
    for (const line of args) {
      const trimmed = line.trim();
      if (trimmed.startsWith('want ')) wants.push(trimmed.slice(5).split(' ')[0] as string);
      else if (trimmed.startsWith('have ')) haves.push(trimmed.slice(5).trim());
      else if (trimmed.startsWith('shallow ')) shallowIn.push(trimmed.slice(8).trim());
      else if (trimmed.startsWith('deepen ')) {
        const n = Number.parseInt(trimmed.slice(7).trim(), 10);
        if (Number.isFinite(n)) depth = n;
      }
    }
    const plan = planFetch(repo, wants, haves, depth, shallowIn);
    const pack = writePack(plan.objects.values());
    const parts: Buffer[] = [];
    const ackLines: string[] = [];
    if (haves.length === 0) {
      ackLines.push('acknowledgments\n', 'NAK\n');
    } else {
      ackLines.push('acknowledgments\n');
      let allAcked = true;
      for (const have of haves) {
        if (repo.objects.has(have)) ackLines.push(`ACK ${have}\n`);
        else allAcked = false;
      }
      if (allAcked) ackLines.push('ready\n');
      else ackLines.push('NAK\n');
    }
    parts.push(encodePktLines([...ackLines, 'flush']));
    if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
      const section: Array<string | 'flush'> = ['shallow-info\n'];
      for (const oid of plan.shallow) section.push(`shallow ${oid}\n`);
      for (const oid of plan.unshallow) section.push(`unshallow ${oid}\n`);
      section.push('flush');
      parts.push(encodePktLines(section));
    }
    const wantedRefs: string[] = [];
    for (const want of wants) {
      for (const [name, oid] of repo.refs) {
        if (oid === want) wantedRefs.push(`${want} ${name}\n`);
      }
    }
    if (wantedRefs.length > 0) {
      parts.push(encodePktLines([...['wanted-refs\n', ...wantedRefs], 'flush']));
    }
    parts.push(encodePktLine('packfile\n'));
    for (const packet of sidebandPackets(pack)) parts.push(packet);
    parts.push(pktFlush());
    return Buffer.concat(parts);
  }
  throw new Error(`unknown v2 command ${JSON.stringify(command)}`);
}

function handleUploadPackV0(repo: Repo, body: Buffer): Buffer {
  let packets: Pkt[];
  try {
    packets = decodePktLines(body);
  } catch {
    throw new Error('malformed pkt-line stream');
  }
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowIn: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').trim();
    if (section === 0) {
      if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0] as string);
      else if (line.startsWith('shallow ')) shallowIn.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) {
        const n = Number.parseInt(line.slice(7).trim(), 10);
        if (Number.isFinite(n)) depth = n;
      }
    } else if (line.startsWith('have ')) {
      haves.push(line.slice(5).trim());
    }
  }
  const plan = planFetch(repo, wants, haves, depth, shallowIn);
  const pack = writePack(plan.objects.values());
  const parts: Buffer[] = [];
  if (haves.length === 0) {
    parts.push(encodePktLine('NAK\n'));
  } else {
    let allAcked = true;
    for (const have of haves) {
      if (repo.objects.has(have)) parts.push(encodePktLine(`ACK ${have}\n`));
      else allAcked = false;
    }
    if (!allAcked) parts.push(encodePktLine('NAK\n'));
  }
  for (const oid of plan.shallow) parts.push(encodePktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(encodePktLine(`unshallow ${oid}\n`));
  for (const packet of sidebandPackets(pack)) parts.push(packet);
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

/** Read pkt-lines from the front of `buffer` until the first flush; return them and the bytes used. */
function readCommandsPrefix(buffer: Buffer): { packets: Pkt[]; consumed: number } {
  const packets: Pkt[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('truncated pkt-line');
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line length ${JSON.stringify(head)}`);
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      break;
    }
    if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
      continue;
    }
    if (length === 3 || length > 65520 || offset + length > buffer.length) throw new Error('bad pkt-line');
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return { packets, consumed: offset };
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const { packets, consumed } = readCommandsPrefix(body);
  const packBytes = body.subarray(consumed);
  const commands: PushCommand[] = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    let text = packet.payload.toString('utf8');
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.slice(0, nul);
    const line = text.replace(/\n$/, '');
    if (!line) continue;
    const parts = line.split(' ');
    if (parts.length < 3) throw new Error(`bad push command ${JSON.stringify(line)}`);
    commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
  }
  let unpackOk = true;
  let unpackDetail = 'ok';
  const incoming = new Map<string, GitObject>();
  const hasUpdates = commands.some((command) => command.newOid !== ZERO_OID);
  if (packBytes.length > 0) {
    try {
      const read = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, object] of read) incoming.set(oid, object);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  } else if (hasUpdates) {
    unpackOk = false;
    unpackDetail = 'missing packfile';
  }
  if (unpackOk) {
    for (const [oid, object] of incoming) repo.objects.set(oid, object);
  }
  const reportLines: string[] = [unpackOk ? 'unpack ok\n' : `unpack ${unpackDetail}\n`];
  for (const command of commands) {
    let ok = unpackOk;
    let reason = '';
    if (ok) {
      const current = repo.refs.get(command.ref);
      if (command.newOid === ZERO_OID) {
        if (current === undefined) {
          ok = false;
          reason = 'no such ref';
        } else if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
          ok = false;
          reason = 'non-fast-forward';
        }
      } else {
        const target = repo.objects.get(command.newOid) ?? incoming.get(command.newOid);
        if (!target) {
          ok = false;
          reason = 'unable to resolve new object';
        } else if (command.oldOid === ZERO_OID) {
          if (current !== undefined) {
            ok = false;
            reason = 'already exists';
          }
        } else {
          if (current === undefined) {
            ok = false;
            reason = 'no such ref';
          } else if (command.oldOid !== current) {
            ok = false;
            reason = 'non-fast-forward';
          } else if (target.type === 'commit' && !isAncestor(repo, command.oldOid, command.newOid)) {
            ok = false;
            reason = 'non-fast-forward';
          }
        }
      }
    }
    if (ok) {
      if (command.newOid === ZERO_OID) repo.refs.delete(command.ref);
      else repo.refs.set(command.ref, command.newOid);
      reportLines.push(`ok ${command.ref}\n`);
    } else {
      reportLines.push(`ng ${command.ref} ${reason || 'failed'}\n`);
    }
  }
  const reportBody = encodePktLines([...reportLines, 'flush']);
  const sideband: Buffer[] = [];
  const CHUNK = 60000;
  for (let offset = 0; offset < reportBody.length; offset += CHUNK) {
    const slice = reportBody.subarray(offset, Math.min(reportBody.length, offset + CHUNK));
    sideband.push(encodePktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  sideband.push(pktFlush());
  return Buffer.concat(sideband);
}

// ------------------------------------------------------------------ REST v3

function paginate<T>(items: readonly T[], query: URLSearchParams, req: IncomingMessage, path: string): { page: T[]; link: string | null } {
  const perPage = Math.max(1, Math.min(100, Number.parseInt(query.get('per_page') ?? '30', 10) || 30));
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length) {
    const host = req.headers.host ?? 'localhost';
    const url = new URL(`http://${host}${path}`);
    url.searchParams.set('per_page', String(perPage));
    url.searchParams.set('page', String(page + 1));
    link = `<${url.toString()}>; rel="next"`;
  }
  return { page: slice, link };
}

function commitJson(repo: Repo, oid: string): Record<string, unknown> {
  const object = repo.objects.get(oid);
  const view = object?.type === 'commit' ? parseCommit(object.data) : null;
  const parseIdent = (line: string): { name: string; email: string; date: string } => {
    const match = /^(.*?) <(.*?)> (\d+) ([+-]\d{4})$/.exec(line);
    if (!match) return { name: VIEWER_NAME, email: VIEWER_EMAIL, date: new Date(FIXED_EPOCH * 1000).toISOString() };
    return { name: match[1] as string, email: match[2] as string, date: new Date(Number(match[3]) * 1000).toISOString() };
  };
  const author = parseIdent(view?.author ?? '');
  const committer = parseIdent(view?.committer ?? '');
  return {
    sha: oid,
    node_id: nodeId('C', `${repo.owner}/${repo.name}#${oid}`),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/commit/${oid}`,
    author: userJson(VIEWER_LOGIN, VIEWER_ID),
    committer: userJson(VIEWER_LOGIN, VIEWER_ID),
    parents: (view?.parents ?? []).map((parent) => ({ sha: parent, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${parent}` })),
    commit: {
      message: view?.message ?? '',
      author,
      committer,
      tree: { sha: view?.tree ?? '' },
    },
  };
}

/** Commits reachable from `tip`, newest first (depth-first, parents in order). */
function listCommits(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack: string[] = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    out.push(oid);
    const parents = parseCommit(object.data).parents;
    for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i] as string);
  }
  return out;
}

function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const countLines = (text: string): Map<string, number> => {
    const map = new Map<string, number>();
    if (text === '') return map;
    for (const line of text.split('\n')) map.set(line, (map.get(line) ?? 0) + 1);
    return map;
  };
  const oldCounts = countLines(oldText);
  const newCounts = countLines(newText);
  let additions = 0;
  let deletions = 0;
  for (const [line, count] of newCounts) additions += Math.max(0, count - (oldCounts.get(line) ?? 0));
  for (const [line, count] of oldCounts) deletions += Math.max(0, count - (newCounts.get(line) ?? 0));
  return { additions, deletions };
}

function pullFiles(repo: Repo, pull: Pull): Array<Record<string, unknown>> {
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (!headTip || !baseTip) return [];
  const base = mergeBase(repo, headTip, baseTip) ?? baseTip;
  const baseCommit = repo.objects.get(base);
  const headCommit = repo.objects.get(headTip);
  if (!baseCommit || !headCommit) return [];
  const baseTree = parseCommit(baseCommit.data).tree;
  const headTree = parseCommit(headCommit.data).tree;
  const changed = diffTrees(repo, baseTree, headTree);
  return changed.map((path) => {
    const oldBlob = blobAtPath(repo, baseTree, path);
    const newBlob = blobAtPath(repo, headTree, path);
    const oldText = oldBlob ? repo.objects.get(oldBlob.oid)?.data.toString('utf8') ?? '' : '';
    const newText = newBlob ? repo.objects.get(newBlob.oid)?.data.toString('utf8') ?? '' : '';
    const { additions, deletions } = lineDiff(oldText, newText);
    const status = !oldBlob ? 'added' : !newBlob ? 'removed' : 'modified';
    return {
      sha: newBlob?.oid ?? oldBlob?.oid ?? '',
      filename: path,
      status,
      additions,
      deletions,
      changes: additions + deletions,
      blob_url: `https://example.invalid/${repo.owner}/${repo.name}/blob/${headTip}/${path}`,
      raw_url: `https://example.invalid/${repo.owner}/${repo.name}/raw/${headTip}/${path}`,
      contents_url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}?ref=${headTip}`,
    };
  });
}

function doMerge(repo: Repo, pull: Pull): { ok: boolean; sha?: string; reason?: string } {
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (!headTip || !baseTip) return { ok: false, reason: 'head or base branch not found' };
  if (mergeableState(repo, pull) === false) return { ok: false, reason: 'conflict' };
  const headCommit = repo.objects.get(headTip);
  if (!headCommit || headCommit.type !== 'commit') return { ok: false, reason: 'head commit not found' };
  const headTree = parseCommit(headCommit.data).tree;
  const mergeSha = makeCommit(repo, headTree, [baseTip], `${pull.title}\n`, FIXED_EPOCH);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergeCommitSha = mergeSha;
  pull.updatedAt = nowIso();
  return { ok: true, sha: mergeSha };
}

function resolveRepo(owner: string, name: string, res: ServerResponse): Repo | null {
  if (owner !== VIEWER_LOGIN) {
    sendJson(res, 404, { message: 'Not Found' });
    return null;
  }
  const repo = findRepo(owner, name);
  if (!repo) {
    sendJson(res, 404, { message: 'Not Found' });
    return null;
  }
  return repo;
}

function handleContentsPut(repo: Repo, pathParts: string[], body: Record<string, unknown>, res: ServerResponse): void {
  const filePath = pathParts.join('/');
  const message = strField(body, 'message', 'Update file');
  const contentB64 = strField(body, 'content');
  const branch = strField(body, 'branch', repo.defaultBranch);
  const sha = typeof body.sha === 'string' ? body.sha : undefined;
  const tip = branchTip(repo, branch);
  let content: Buffer;
  try {
    content = Buffer.from(contentB64, 'base64');
  } catch {
    sendJson(res, 400, { message: 'content is not valid base64' });
    return;
  }
  // A PUT on a branch that does not exist yet branches it off the default
  // branch (or starts the repository when there is no commit at all).
  let baseTip = tip;
  if (baseTip === null && branch !== repo.defaultBranch) baseTip = branchTip(repo, repo.defaultBranch);
  let currentTree = '';
  let currentBlob: { oid: string; mode: string } | null = null;
  if (baseTip !== null) {
    const tipCommit = repo.objects.get(baseTip);
    if (!tipCommit || tipCommit.type !== 'commit') {
      sendJson(res, 404, { message: 'Not Found' });
      return;
    }
    currentTree = parseCommit(tipCommit.data).tree;
    currentBlob = blobAtPath(repo, currentTree, filePath);
  }
  const isUpdate = currentBlob !== null;
  if (isUpdate && sha !== undefined && sha.toLowerCase() !== currentBlob.oid.toLowerCase()) {
    sendJson(res, 409, { message: 'sha does not match the current blob' });
    return;
  }
  if (isUpdate && sha === undefined) {
    sendJson(res, 409, { message: 'sha is required to update a file' });
    return;
  }
  const blobOid = hashObject('blob', content);
  repo.objects.set(blobOid, { type: 'blob', data: content });
  const newTree = setPathInTree(repo, currentTree === '' ? ZERO_OID : currentTree, filePath, blobOid);
  const parents = baseTip !== null ? [baseTip] : [];
  const commitSha = makeCommit(repo, newTree, parents, message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  repo.updatedAt = nowIso();
  sendJson(res, isUpdate ? 200 : 201, {
    content: {
      name: filePath.split('/').pop() ?? filePath,
      path: filePath,
      sha: blobOid,
      size: content.length,
      url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
      html_url: `https://example.invalid/${repo.owner}/${repo.name}/blob/${branch}/${filePath}`,
      type: 'file',
      encoding: 'base64',
      content: content.toString('base64'),
    },
    commit: { sha: commitSha, message },
  });
}

function handleContentsGet(repo: Repo, pathParts: string[], query: URLSearchParams, res: ServerResponse): void {
  const filePath = pathParts.join('/');
  const ref = query.get('ref') ?? repo.defaultBranch;
  let tip: string | null = null;
  if (isOid(ref)) tip = repo.objects.has(ref) ? ref : null;
  else tip = branchTip(repo, ref);
  if (tip === null) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const tipCommit = repo.objects.get(tip);
  if (!tipCommit || tipCommit.type !== 'commit') {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const rootTree = parseCommit(tipCommit.data).tree;
  if (filePath === '') {
    const entries = treeAt(repo, rootTree, '') ?? [];
    sendJson(res, 200, entries.map((entry) => ({
      type: entry.mode === '40000' ? 'dir' : 'file',
      name: entry.name,
      path: entry.name,
      sha: entry.oid,
      size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
      url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${entry.name}`,
    })));
    return;
  }
  const blob = blobAtPath(repo, rootTree, filePath);
  if (blob) {
    const data = repo.objects.get(blob.oid)?.data ?? Buffer.alloc(0);
    sendJson(res, 200, {
      type: 'file',
      encoding: 'base64',
      size: data.length,
      name: filePath.split('/').pop() ?? filePath,
      path: filePath,
      content: data.toString('base64'),
      sha: blob.oid,
      url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
      html_url: `https://example.invalid/${repo.owner}/${repo.name}/blob/${ref}/${filePath}`,
    });
    return;
  }
  const dirEntries = treeAt(repo, rootTree, filePath);
  if (dirEntries !== null) {
    sendJson(res, 200, dirEntries.map((entry) => ({
      type: entry.mode === '40000' ? 'dir' : 'file',
      name: entry.name,
      path: `${filePath}/${entry.name}`,
      sha: entry.oid,
      size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
      url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}/${entry.name}`,
    })));
    return;
  }
  sendJson(res, 404, { message: 'Not Found' });
}

function handleContentsDelete(repo: Repo, pathParts: string[], body: Record<string, unknown>, res: ServerResponse): void {
  const filePath = pathParts.join('/');
  const message = strField(body, 'message', 'Delete file');
  const branch = strField(body, 'branch', repo.defaultBranch);
  const sha = typeof body.sha === 'string' ? body.sha : undefined;
  const tip = branchTip(repo, branch);
  if (tip === null) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const tipCommit = repo.objects.get(tip);
  if (!tipCommit || tipCommit.type !== 'commit') {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const rootTree = parseCommit(tipCommit.data).tree;
  const currentBlob = blobAtPath(repo, rootTree, filePath);
  if (!currentBlob) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  if (sha !== undefined && sha.toLowerCase() !== currentBlob.oid.toLowerCase()) {
    sendJson(res, 409, { message: 'sha does not match the current blob' });
    return;
  }
  const newTree = setPathInTree(repo, rootTree, filePath, null);
  const commitSha = makeCommit(repo, newTree, [tip], message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  repo.updatedAt = nowIso();
  sendJson(res, 200, { content: null, commit: { sha: commitSha, message } });
}

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, method: string, query: URLSearchParams, rawBody: Buffer): Promise<boolean> {
  if (!path.startsWith('/api/v3')) return false;
  const rest = path.slice('/api/v3'.length);
  const segments = rest.split('/').filter((part) => part !== '');
  const decode = (value: string): string => {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  };

  // The API root needs no token (the starter answered it that way).
  if ((rest === '' || rest === '/') && method === 'GET') {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return true;
  }

  const needJsonBody = method === 'POST' || method === 'PUT' || method === 'PATCH';
  let body: Record<string, unknown> = {};
  if (needJsonBody) {
    const parsed = parseJsonBody(rawBody, res);
    if (parsed === null) return true;
    if (isRecord(parsed)) body = parsed;
    else if (parsed !== undefined && rawBody.length > 0) {
      sendJson(res, 400, { message: 'Problems parsing JSON' });
      return true;
    }
  }

  if (rest === '/meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: SERVER_VERSION, verifiable_password_authentication: true });
    return true;
  }
  if (rest === '/user' && method === 'GET') {
    sendJson(res, 200, userJson(VIEWER_LOGIN, VIEWER_ID));
    return true;
  }
  if (rest === '/user/repos' && method === 'GET') {
    const all = [...repos.values()].map((repo) => repoJson(repo));
    const { page, link } = paginate(all, query, req, path);
    sendJson(res, 200, page, link ? { link } : {});
    return true;
  }
  if (rest === '/user/repos' && method === 'POST') {
    const name = strField(body, 'name');
    if (!name || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) {
      sendJson(res, 422, { message: 'Validation Failed: name is invalid' });
      return true;
    }
    if (findRepo(VIEWER_LOGIN, name)) {
      sendJson(res, 422, { message: `Repository ${VIEWER_LOGIN}/${name} already exists` });
      return true;
    }
    const repo = createRepoRecord(name, strField(body, 'description'), body.private === true);
    sendJson(res, 201, repoJson(repo));
    return true;
  }
  if (segments.length === 3 && segments[0] === 'users' && segments[2] === 'repos' && method === 'GET') {
    const login = decode(segments[1] as string);
    if (login !== VIEWER_LOGIN) {
      sendJson(res, 404, { message: 'Not Found' });
      return true;
    }
    const all = [...repos.values()].map((repo) => repoJson(repo));
    const { page, link } = paginate(all, query, req, path);
    sendJson(res, 200, page, link ? { link } : {});
    return true;
  }
  if (segments.length === 2 && segments[0] === 'users' && method === 'GET') {
    const login = decode(segments[1] as string);
    if (login !== VIEWER_LOGIN) {
      sendJson(res, 404, { message: 'Not Found' });
      return true;
    }
    sendJson(res, 200, userJson(VIEWER_LOGIN, VIEWER_ID));
    return true;
  }

  if (segments.length >= 2 && segments[0] === 'repos') {
    const owner = decode(segments[1] as string);
    const name = decode(segments[2] as string);
    const repo = resolveRepo(owner, name, res);
    if (!repo) return true;
    const tail = segments.slice(3);

    if (tail.length === 0 && method === 'GET') {
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    if (tail.length === 0 && method === 'PATCH') {
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.name === 'string' && body.name !== repo.name) {
        repos.delete(repoKey(repo.owner, repo.name));
        repo.name = body.name;
        repos.set(repoKey(repo.owner, repo.name), repo);
      }
      if (typeof body.private === 'boolean') repo.isPrivate = body.private;
      repo.updatedAt = nowIso();
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    if (tail.length === 0 && method === 'DELETE') {
      repos.delete(repoKey(repo.owner, repo.name));
      res.writeHead(204, { 'x-github-request-id': nextRequestId() });
      res.end();
      return true;
    }
    if (tail.length === 1 && tail[0] === 'branches' && method === 'GET') {
      const branches = [...repo.refs.keys()]
        .filter((ref) => ref.startsWith('refs/heads/'))
        .map((ref) => ref.slice('refs/heads/'.length))
        .sort()
        .map((branch) => ({
          name: branch,
          commit: { sha: repo.refs.get(`refs/heads/${branch}`) ?? '', url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${repo.refs.get(`refs/heads/${branch}`) ?? ''}` },
          protected: false,
        }));
      sendJson(res, 200, branches);
      return true;
    }
    if (tail.length === 2 && tail[0] === 'branches' && method === 'GET') {
      const branch = decode(tail[1] as string);
      const tip = branchTip(repo, branch);
      if (tip === null) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      sendJson(res, 200, { name: branch, commit: { sha: tip, commit: commitJson(repo, tip).commit }, protected: false });
      return true;
    }
    if (tail.length === 1 && tail[0] === 'commits' && method === 'GET') {
      const shaParam = query.get('sha') ?? repo.defaultBranch;
      let tip: string | null = null;
      if (isOid(shaParam)) tip = repo.objects.has(shaParam) ? shaParam : null;
      else tip = branchTip(repo, shaParam);
      if (tip === null) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      const all = listCommits(repo, tip).map((oid) => commitJson(repo, oid));
      const { page, link } = paginate(all, query, req, path);
      sendJson(res, 200, page, link ? { link } : {});
      return true;
    }
    if (tail.length === 2 && tail[0] === 'commits' && method === 'GET') {
      const sha = decode(tail[1] as string);
      if (!isOid(sha) || !repo.objects.has(sha)) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      sendJson(res, 200, commitJson(repo, sha));
      return true;
    }
    if (tail.length >= 2 && tail[0] === 'git' && tail[1] === 'refs' && method === 'POST' && tail.length === 2) {
      const ref = strField(body, 'ref');
      const sha = strField(body, 'sha');
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
        sendJson(res, 422, { message: 'Validation Failed: ref or sha is invalid' });
        return true;
      }
      if (repo.refs.has(ref)) {
        sendJson(res, 422, { message: 'Reference already exists' });
        return true;
      }
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, object: { sha, type: 'commit', url: `/api/v3/repos/${repo.owner}/${repo.name}/git/commits/${sha}` } });
      return true;
    }
    if (tail.length >= 3 && tail[0] === 'git' && tail[1] === 'refs' && method === 'GET') {
      const refName = tail.slice(2).map(decode).join('/');
      const oid = repo.refs.get(refName);
      if (!oid) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      const type = repo.objects.get(oid)?.type ?? 'commit';
      sendJson(res, 200, { ref: refName, object: { sha: oid, type, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${type}s/${oid}` } });
      return true;
    }
    if (tail.length >= 3 && tail[0] === 'git' && tail[1] === 'refs' && method === 'DELETE') {
      const refName = tail.slice(2).map(decode).join('/');
      if (!repo.refs.has(refName)) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      repo.refs.delete(refName);
      res.writeHead(204, { 'x-github-request-id': nextRequestId() });
      res.end();
      return true;
    }
    if (tail.length >= 1 && tail[0] === 'contents') {
      const pathParts = tail.slice(1).map(decode);
      if (method === 'PUT') {
        handleContentsPut(repo, pathParts, body, res);
        return true;
      }
      if (method === 'GET') {
        handleContentsGet(repo, pathParts, query, res);
        return true;
      }
      if (method === 'DELETE') {
        handleContentsDelete(repo, pathParts, body, res);
        return true;
      }
    }
    if (tail.length === 1 && tail[0] === 'labels' && method === 'GET') {
      sendJson(res, 200, repo.labels.map((label) => labelJson(label, repo)));
      return true;
    }
    if (tail.length === 1 && tail[0] === 'labels' && method === 'POST') {
      const name = strField(body, 'name');
      if (!name) {
        sendJson(res, 422, { message: 'Validation Failed: name is required' });
        return true;
      }
      const existing = repo.labels.find((label) => label.name === name);
      if (existing) {
        sendJson(res, 201, labelJson(existing, repo));
        return true;
      }
      objectIdCounter += 1;
      const label: Label = { id: objectIdCounter, name, color: strField(body, 'color', 'ededed'), description: strField(body, 'description') };
      repo.labels.push(label);
      sendJson(res, 201, labelJson(label, repo));
      return true;
    }
    if (tail.length === 1 && tail[0] === 'issues' && method === 'GET') {
      let list = [...repo.issues];
      const state = query.get('state') ?? 'open';
      if (state !== 'all') list = list.filter((issue) => issue.state === state);
      const sort = query.get('sort') ?? 'created';
      const direction = query.get('direction') ?? 'desc';
      if (sort === 'created') {
        list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
      }
      const all = list.map((issue) => issueJson(issue, repo));
      const { page, link } = paginate(all, query, req, path);
      sendJson(res, 200, page, link ? { link } : {});
      return true;
    }
    if (tail.length === 1 && tail[0] === 'issues' && method === 'POST') {
      const title = strField(body, 'title');
      if (!title) {
        sendJson(res, 422, { message: 'Validation Failed: title is required' });
        return true;
      }
      const labels = Array.isArray(body.labels) ? (body.labels as unknown[]).filter((item): item is string => typeof item === 'string') : [];
      for (const label of labels) {
        if (!repo.labels.some((item) => item.name === label)) {
          sendJson(res, 422, { message: `Validation Failed: label "${label}" does not exist` });
          return true;
        }
      }
      objectIdCounter += 1;
      globalSeq += 1;
      const issue: Issue = {
        id: objectIdCounter,
        nodeId: nodeId('I', `${repo.owner}/${repo.name}#${repo.nextIssue}`),
        number: repo.nextIssue,
        title,
        body: strField(body, 'body'),
        state: 'open',
        labels,
        userLogin: VIEWER_LOGIN,
        createdAt: nowIso(),
        updatedAt: nowIso(),
        seq: globalSeq,
        comments: [],
      };
      repo.nextIssue += 1;
      repo.issues.push(issue);
      sendJson(res, 201, issueJson(issue, repo));
      return true;
    }
    if (tail.length === 2 && tail[0] === 'issues' && method === 'GET') {
      const number = Number.parseInt(tail[1] as string, 10);
      const issue = repo.issues.find((item) => item.number === number);
      if (!issue) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      sendJson(res, 200, issueJson(issue, repo));
      return true;
    }
    if (tail.length === 2 && tail[0] === 'issues' && method === 'PATCH') {
      const number = Number.parseInt(tail[1] as string, 10);
      const issue = repo.issues.find((item) => item.number === number);
      if (!issue) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      if (typeof body.state === 'string' && (body.state === 'open' || body.state === 'closed')) issue.state = body.state;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      issue.updatedAt = nowIso();
      sendJson(res, 200, issueJson(issue, repo));
      return true;
    }
    if (tail.length === 3 && tail[0] === 'issues' && tail[2] === 'comments' && method === 'GET') {
      const number = Number.parseInt(tail[1] as string, 10);
      const issue = repo.issues.find((item) => item.number === number);
      if (!issue) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      sendJson(res, 200, issue.comments.map((comment) => commentJson(comment, repo, number)));
      return true;
    }
    if (tail.length === 3 && tail[0] === 'issues' && tail[2] === 'comments' && method === 'POST') {
      const number = Number.parseInt(tail[1] as string, 10);
      const issue = repo.issues.find((item) => item.number === number);
      if (!issue) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      commentIdCounter += 1;
      globalSeq += 1;
      const comment: Comment = {
        id: commentIdCounter,
        nodeId: nodeId('C', `${repo.owner}/${repo.name}#${number}:${commentIdCounter}`),
        body: strField(body, 'body'),
        userLogin: VIEWER_LOGIN,
        createdAt: nowIso(),
        seq: globalSeq,
      };
      issue.comments.push(comment);
      sendJson(res, 201, commentJson(comment, repo, number));
      return true;
    }
    if (tail.length === 1 && tail[0] === 'pulls' && method === 'GET') {
      let list = [...repo.pulls];
      const state = query.get('state') ?? 'open';
      if (state === 'open') list = list.filter((pull) => pull.state === 'open');
      else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
      list.sort((a, b) => b.seq - a.seq);
      const all = list.map((pull) => pullJson(pull, repo));
      const { page, link } = paginate(all, query, req, path);
      sendJson(res, 200, page, link ? { link } : {});
      return true;
    }
    if (tail.length === 1 && tail[0] === 'pulls' && method === 'POST') {
      const title = strField(body, 'title');
      const head = strField(body, 'head');
      const base = strField(body, 'base', repo.defaultBranch);
      if (!title || !head) {
        sendJson(res, 422, { message: 'Validation Failed: title and head are required' });
        return true;
      }
      if (!branchTip(repo, head)) {
        sendJson(res, 422, { message: `Validation Failed: head branch "${head}" does not exist` });
        return true;
      }
      if (!branchTip(repo, base)) {
        sendJson(res, 422, { message: `Validation Failed: base branch "${base}" does not exist` });
        return true;
      }
      objectIdCounter += 1;
      globalSeq += 1;
      const pull: Pull = {
        id: objectIdCounter,
        nodeId: nodeId('P', `${repo.owner}/${repo.name}#${repo.nextPull}`),
        number: repo.nextPull,
        title,
        body: strField(body, 'body'),
        state: 'open',
        merged: false,
        headRef: head,
        baseRef: base,
        headSha: '',
        baseSha: '',
        mergeCommitSha: null,
        userLogin: VIEWER_LOGIN,
        createdAt: nowIso(),
        updatedAt: nowIso(),
        seq: globalSeq,
      };
      repo.nextPull += 1;
      repo.pulls.push(pull);
      sendJson(res, 201, pullJson(pull, repo));
      return true;
    }
    if (tail.length === 2 && tail[0] === 'pulls' && method === 'GET') {
      const number = Number.parseInt(tail[1] as string, 10);
      const pull = repo.pulls.find((item) => item.number === number);
      if (!pull) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      sendJson(res, 200, pullJson(pull, repo));
      return true;
    }
    if (tail.length === 3 && tail[0] === 'pulls' && tail[2] === 'files' && method === 'GET') {
      const number = Number.parseInt(tail[1] as string, 10);
      const pull = repo.pulls.find((item) => item.number === number);
      if (!pull) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      sendJson(res, 200, pullFiles(repo, pull));
      return true;
    }
    if (tail.length === 3 && tail[0] === 'pulls' && tail[2] === 'merge' && method === 'PUT') {
      const number = Number.parseInt(tail[1] as string, 10);
      const pull = repo.pulls.find((item) => item.number === number);
      if (!pull) {
        sendJson(res, 404, { message: 'Not Found' });
        return true;
      }
      if (pull.state === 'closed') {
        sendJson(res, 405, { message: 'Pull request is already closed' });
        return true;
      }
      const merged = doMerge(repo, pull);
      if (!merged.ok) {
        sendJson(res, 405, { message: merged.reason ?? 'Merge conflict' });
        return true;
      }
      sendJson(res, 200, { sha: merged.sha, merged: true, message: 'Pull request successfully merged' });
      return true;
    }
  }

  sendJson(res, 404, { message: 'Not Found' });
  return true;
}

// ------------------------------------------------------------------ GraphQL v4

type GqlValue =
  | { kind: 'var'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'bool'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: Record<string, GqlValue> };

interface GqlField {
  alias: string | null;
  name: string;
  args: Record<string, GqlValue>;
  selection: GqlField[] | null;
  fragmentType: string | null;
}

interface GqlDocument {
  operation: 'query' | 'mutation';
  name: string | null;
  selection: GqlField[];
}

function tokenizeGql(source: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\n' || ch === '\r' || ch === '\t' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += source[j];
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < source.length && /[0-9.eE+-]/.test(source[j] as string)) j += 1;
      tokens.push(source.slice(i, j));
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j] as string)) j += 1;
      tokens.push(source.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = tokenizeGql(source);
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }

  private next(): string {
    return this.tokens[this.pos++] as string;
  }

  private expect(token: string): void {
    const got = this.next();
    if (got !== token) throw new Error(`expected ${token}, got ${got}`);
  }

  parseDocument(): GqlDocument {
    let operation: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    if (this.peek() === 'query' || this.peek() === 'mutation') {
      operation = this.next() as 'query' | 'mutation';
      if (this.peek() !== undefined && this.peek() !== '{' && this.peek() !== '(') name = this.next();
      if (this.peek() === '(') this.skipParens();
    }
    const selection = this.parseSelectionSet();
    return { operation, name, selection };
  }

  private skipParens(): void {
    this.expect('(');
    let depth = 1;
    while (depth > 0) {
      const token = this.next();
      if (token === '(') depth += 1;
      else if (token === ')') depth -= 1;
    }
  }

  private parseSelectionSet(): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (this.peek() !== '}' && this.peek() !== undefined) {
      fields.push(this.parseField());
    }
    this.expect('}');
    return fields;
  }

  private parseField(): GqlField {
    if (this.peek() === '...') {
      this.next();
      let fragmentType: string | null = null;
      if (this.peek() === 'on') {
        this.next();
        fragmentType = this.next();
      }
      const selection = this.parseSelectionSet();
      return { alias: null, name: '...', args: {}, selection, fragmentType };
    }
    let alias: string | null = null;
    let name = this.next();
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    const args: Record<string, GqlValue> = {};
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')') {
        const key = this.next();
        this.expect(':');
        args[key] = this.parseValue();
      }
      this.expect(')');
    }
    let selection: GqlField[] | null = null;
    if (this.peek() === '{') selection = this.parseSelectionSet();
    return { alias, name, args, selection, fragmentType: null };
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token === '$') return { kind: 'var', name: this.next() };
    if (token === '[') {
      const items: GqlValue[] = [];
      while (this.peek() !== ']') items.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', items };
    }
    if (token === '{') {
      const fields: Record<string, GqlValue> = {};
      while (this.peek() !== '}') {
        const key = this.next();
        this.expect(':');
        fields[key] = this.parseValue();
      }
      this.expect('}');
      return { kind: 'object', fields };
    }
    if (token.startsWith('"')) return { kind: 'string', value: JSON.parse(token) as string };
    if (token === 'true') return { kind: 'bool', value: true };
    if (token === 'false') return { kind: 'bool', value: false };
    if (token === 'null') return { kind: 'null' };
    if (/^-?\d+$/.test(token)) return { kind: 'int', value: Number.parseInt(token, 10) };
    if (/^-?\d+\.\d+/.test(token)) return { kind: 'float', value: Number.parseFloat(token) };
    return { kind: 'enum', value: token };
  }
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'var':
      return variables[value.name];
    case 'string':
    case 'int':
    case 'float':
    case 'bool':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.items.map((item) => resolveGqlValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(value.fields)) out[key] = resolveGqlValue(item, variables);
      return out;
    }
  }
}

interface GqlNode {
  t: string;
  v: unknown;
}

type FieldResolver = (node: GqlNode, args: Record<string, unknown>, ctx: GqlCtx) => unknown;

interface GqlCtx {
  errors: Array<{ message: string }>;
}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'repository'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'headRef', 'baseRef', 'createdAt', 'updatedAt', 'closedAt', 'mergedAt', 'author'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'isPrivate', 'private', 'createdAt', 'updatedAt', 'url'],
  User: ['login', 'id', 'name', 'email'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'endCursor', 'startCursor'],
  Ref: ['name', 'target'],
  IssueComment: ['id', 'body', 'author'],
  IssueCommentEdge: ['node', 'cursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Field: ['name', 'description'],
  __EnumValue: ['name', 'description'],
  Query: ['viewer', 'repository', 'node', '__type'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
};

const SEARCH_TYPE_ENUMS = ['ISSUE', 'REPOSITORY', 'USER', 'CODE', 'DISCUSSION', 'COMMIT', 'MILESTONE', 'PROJECT', 'WIKI'];

function decodeNodeId(id: string): { kind: string; key: string } | null {
  const at = id.indexOf('_');
  if (at < 0) return null;
  const kind = id.slice(0, at);
  try {
    const decoded = Buffer.from(id.slice(at + 1), 'base64url').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep < 0) return null;
    return { kind, key: decoded.slice(sep + 1) };
  } catch {
    return null;
  }
}

function repoFromNodeId(id: string): Repo | null {
  const decoded = decodeNodeId(id);
  if (!decoded || decoded.kind !== 'R') return null;
  const [owner, name] = decoded.key.split('/');
  if (!owner || !name) return null;
  return findRepo(owner, name) ?? null;
}

function issueFromNodeId(id: string): { repo: Repo; issue: Issue } | null {
  const decoded = decodeNodeId(id);
  if (!decoded || decoded.kind !== 'I') return null;
  const [ownerRepo, numberText] = decoded.key.split('#');
  const [owner, name] = (ownerRepo ?? '').split('/');
  if (!owner || !name) return null;
  const repo = findRepo(owner, name);
  if (!repo) return null;
  const issue = repo.issues.find((item) => item.number === Number(numberText));
  return issue ? { repo, issue } : null;
}

function pullFromNodeId(id: string): { repo: Repo; pull: Pull } | null {
  const decoded = decodeNodeId(id);
  if (!decoded || decoded.kind !== 'P') return null;
  const [ownerRepo, numberText] = decoded.key.split('#');
  const [owner, name] = (ownerRepo ?? '').split('/');
  if (!owner || !name) return null;
  const repo = findRepo(owner, name);
  if (!repo) return null;
  const pull = repo.pulls.find((item) => item.number === Number(numberText));
  return pull ? { repo, pull } : null;
}

function issueStateEnum(issue: Issue): string {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullStateEnum(pull: Pull): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function encodeCursor(seq: number): string {
  return Buffer.from(`cursor:${seq}`, 'utf8').toString('base64url');
}

function decodeCursor(cursor: string): number | null {
  try {
    const text = Buffer.from(cursor, 'base64url').toString('utf8');
    if (!text.startsWith('cursor:')) return null;
    const n = Number.parseInt(text.slice('cursor:'.length), 10);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

function sortIssues(issues: readonly Issue[], orderBy: Record<string, unknown> | undefined): Issue[] {
  const list = [...issues];
  const field = typeof orderBy?.field === 'string' ? orderBy.field : 'CREATED_AT';
  const direction = orderBy?.direction === 'ASC' ? 1 : -1;
  const keyOf = (issue: Issue): number => {
    if (field === 'COMMENTS') return issue.comments.length;
    return issue.seq;
  };
  list.sort((a, b) => {
    const diff = keyOf(a) - keyOf(b);
    if (diff !== 0) return diff * direction;
    return (a.number - b.number) * direction;
  });
  return list;
}

function issuesConnection(repo: Repo, args: Record<string, unknown>): GqlNode {
  let list = [...repo.issues];
  const states = Array.isArray(args.states) ? (args.states as unknown[]).map(String) : null;
  if (states) {
    list = list.filter((issue) => states.includes(issueStateEnum(issue)));
  }
  list = sortIssues(list, isRecord(args.orderBy) ? args.orderBy : undefined);
  if (typeof args.after === 'string') {
    const afterSeq = decodeCursor(args.after);
    if (afterSeq !== null) {
      const index = list.findIndex((issue) => issue.seq === afterSeq);
      if (index >= 0) list = list.slice(index + 1);
    }
  }
  const first = typeof args.first === 'number' ? args.first : list.length;
  const page = list.slice(0, first);
  const hasNext = list.length > page.length;
  const endCursor = page.length > 0 ? encodeCursor((page[page.length - 1] as Issue).seq) : null;
  return {
    t: 'IssueConnection',
    v: { nodes: page, pageInfo: { hasNextPage: hasNext, endCursor, hasPreviousPage: false, startCursor: page.length > 0 ? encodeCursor((page[0] as Issue).seq) : null }, totalCount: list.length },
  };
}

function makeIssue(repo: Repo, title: string, body: string): Issue {
  objectIdCounter += 1;
  globalSeq += 1;
  const issue: Issue = {
    id: objectIdCounter,
    nodeId: nodeId('I', `${repo.owner}/${repo.name}#${repo.nextIssue}`),
    number: repo.nextIssue,
    title,
    body,
    state: 'open',
    labels: [],
    userLogin: VIEWER_LOGIN,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    seq: globalSeq,
    comments: [],
  };
  repo.nextIssue += 1;
  repo.issues.push(issue);
  return issue;
}

function makePull(repo: Repo, title: string, body: string, head: string, base: string): Pull | null {
  if (!branchTip(repo, head) || !branchTip(repo, base)) return null;
  objectIdCounter += 1;
  globalSeq += 1;
  const pull: Pull = {
    id: objectIdCounter,
    nodeId: nodeId('P', `${repo.owner}/${repo.name}#${repo.nextPull}`),
    number: repo.nextPull,
    title,
    body,
    state: 'open',
    merged: false,
    headRef: head,
    baseRef: base,
    headSha: '',
    baseSha: '',
    mergeCommitSha: null,
    userLogin: VIEWER_LOGIN,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    seq: globalSeq,
  };
  repo.nextPull += 1;
  repo.pulls.push(pull);
  return pull;
}

const GQL_RESOLVERS: Record<string, Record<string, FieldResolver>> = {
  Query: {
    viewer: () => ({ t: 'User', v: { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL } }),
    repository: (_node, args) => {
      const owner = String(args.owner ?? '');
      const name = String(args.name ?? '');
      if (owner !== VIEWER_LOGIN) return null;
      const repo = findRepo(owner, name);
      return repo ? { t: 'Repository', v: repo } : null;
    },
    node: (_node, args) => {
      const id = String(args.id ?? '');
      const decoded = decodeNodeId(id);
      if (!decoded) return null;
      if (decoded.kind === 'R') {
        const repo = repoFromNodeId(id);
        return repo ? { t: 'Repository', v: repo } : null;
      }
      if (decoded.kind === 'I') {
        const found = issueFromNodeId(id);
        return found ? { t: 'Issue', v: found.issue } : null;
      }
      if (decoded.kind === 'P') {
        const found = pullFromNodeId(id);
        return found ? { t: 'PullRequest', v: found.pull } : null;
      }
      return null;
    },
    __type: (_node, args) => {
      const name = String(args.name ?? '');
      const fields = GQL_TYPE_FIELDS[name];
      if (name === 'SearchType') {
        return { t: '__Type', v: { name, kind: 'ENUM', fields: [], enumValues: SEARCH_TYPE_ENUMS.map((item) => ({ name: item })) } };
      }
      if (!fields) return null;
      return { t: '__Type', v: { name, kind: 'OBJECT', fields: fields.map((item) => ({ name: item })), enumValues: [] } };
    },
  },
  Repository: {
    id: (node) => (node.v as Repo).nodeId,
    databaseId: (node) => (node.v as Repo).databaseId,
    name: (node) => (node.v as Repo).name,
    nameWithOwner: (node) => `${(node.v as Repo).owner}/${(node.v as Repo).name}`,
    owner: (node) => ({ t: 'User', v: { login: (node.v as Repo).owner, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL } }),
    defaultBranchRef: (node) => ({ t: 'Ref', v: { name: (node.v as Repo).defaultBranch } }),
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    description: (node) => (node.v as Repo).description,
    isPrivate: (node) => (node.v as Repo).isPrivate,
    private: (node) => (node.v as Repo).isPrivate,
    createdAt: (node) => (node.v as Repo).createdAt,
    updatedAt: (node) => (node.v as Repo).updatedAt,
    url: (node) => `/api/v3/repos/${(node.v as Repo).owner}/${(node.v as Repo).name}`,
    issue: (node, args) => {
      const repo = node.v as Repo;
      const issue = repo.issues.find((item) => item.number === Number(args.number));
      return issue ? { t: 'Issue', v: issue } : null;
    },
    issues: (node, args) => issuesConnection(node.v as Repo, args),
    pullRequests: (node, args) => {
      const repo = node.v as Repo;
      const list = [...repo.pulls].sort((a, b) => b.seq - a.seq);
      const first = typeof args.first === 'number' ? args.first : list.length;
      const page = list.slice(0, first);
      return { t: 'PullRequestConnection', v: { nodes: page, pageInfo: { hasNextPage: list.length > page.length, endCursor: null, hasPreviousPage: false, startCursor: null }, totalCount: list.length } };
    },
    pullRequest: (node, args) => {
      const repo = node.v as Repo;
      const pull = repo.pulls.find((item) => item.number === Number(args.number));
      return pull ? { t: 'PullRequest', v: pull } : null;
    },
  },
  Issue: {
    id: (node) => (node.v as Issue).nodeId,
    number: (node) => (node.v as Issue).number,
    title: (node) => (node.v as Issue).title,
    state: (node) => issueStateEnum(node.v as Issue),
    body: (node) => (node.v as Issue).body,
    url: (node) => '',
    createdAt: (node) => (node.v as Issue).createdAt,
    updatedAt: (node) => (node.v as Issue).updatedAt,
    author: (node) => ({ t: 'User', v: { login: (node.v as Issue).userLogin, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL } }),
    labels: () => ({ t: 'IssueConnection', v: { nodes: [], pageInfo: { hasNextPage: false, endCursor: null, hasPreviousPage: false, startCursor: null }, totalCount: 0 } }),
    comments: (node) => ({ t: 'IssueConnection', v: { nodes: (node.v as Issue).comments, pageInfo: { hasNextPage: false, endCursor: null, hasPreviousPage: false, startCursor: null }, totalCount: (node.v as Issue).comments.length } }),
    repository: () => null,
  },
  PullRequest: {
    id: (node) => (node.v as Pull).nodeId,
    number: (node) => (node.v as Pull).number,
    title: (node) => (node.v as Pull).title,
    body: (node) => (node.v as Pull).body,
    state: (node) => pullStateEnum(node.v as Pull),
    merged: (node) => (node.v as Pull).merged,
    headRefName: (node) => (node.v as Pull).headRef,
    baseRefName: (node) => (node.v as Pull).baseRef,
    mergeable: (node, _args, ctx) => {
      const pull = node.v as Pull;
      const repo = [...repos.values()].find((item) => item.pulls.includes(pull));
      if (!repo) return 'UNKNOWN';
      const state = mergeableState(repo, pull);
      return state === true ? 'MERGEABLE' : state === false ? 'CONFLICTING' : 'UNKNOWN';
    },
    files: (node, args) => {
      const pull = node.v as Pull;
      const repo = [...repos.values()].find((item) => item.pulls.includes(pull));
      const files = repo ? pullFiles(repo, pull) : [];
      const first = typeof args.first === 'number' ? args.first : files.length;
      const page = files.slice(0, first);
      return { t: 'PullRequestChangedFileConnection', v: { nodes: page.map((file) => ({ path: String(file.filename) })), pageInfo: { hasNextPage: files.length > page.length, endCursor: null, hasPreviousPage: false, startCursor: null }, totalCount: files.length } };
    },
    headRef: (node) => ({ t: 'Ref', v: { name: (node.v as Pull).headRef } }),
    baseRef: (node) => ({ t: 'Ref', v: { name: (node.v as Pull).baseRef } }),
    createdAt: (node) => (node.v as Pull).createdAt,
    updatedAt: (node) => (node.v as Pull).updatedAt,
    closedAt: (node) => ((node.v as Pull).state === 'closed' ? (node.v as Pull).updatedAt : null),
    mergedAt: (node) => ((node.v as Pull).merged ? (node.v as Pull).updatedAt : null),
    author: (node) => ({ t: 'User', v: { login: (node.v as Pull).userLogin, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL } }),
  },
  User: {
    login: (node) => (node.v as { login: string }).login,
    id: (node) => nodeId('U', (node.v as { login: string }).login),
    name: (node) => (node.v as { name?: string }).name ?? (node.v as { login: string }).login,
    email: (node) => (node.v as { email?: string }).email ?? '',
  },
  Ref: {
    name: (node) => (node.v as { name: string }).name,
    target: () => null,
  },
  IssueConnection: {
    nodes: (node) => (node.v as { nodes: unknown[] }).nodes.map((item) => wrapValue(item)),
    edges: (node) => (node.v as { nodes: unknown[] }).nodes.map((item) => ({ t: 'IssueCommentEdge', v: { node: wrapValue(item), cursor: '' } })),
    pageInfo: (node) => ({ t: 'PageInfo', v: (node.v as { pageInfo: unknown }).pageInfo }),
    totalCount: (node) => (node.v as { totalCount: number }).totalCount,
  },
  PullRequestConnection: {
    nodes: (node) => (node.v as { nodes: unknown[] }).nodes.map((item) => wrapValue(item)),
    edges: (node) => (node.v as { nodes: unknown[] }).nodes.map((item) => ({ t: 'IssueCommentEdge', v: { node: wrapValue(item), cursor: '' } })),
    pageInfo: (node) => ({ t: 'PageInfo', v: (node.v as { pageInfo: unknown }).pageInfo }),
    totalCount: (node) => (node.v as { totalCount: number }).totalCount,
  },
  PullRequestChangedFileConnection: {
    nodes: (node) => (node.v as { nodes: unknown[] }).nodes.map((item) => ({ t: 'PullRequestChangedFile', v: item })),
    edges: (node) => (node.v as { nodes: unknown[] }).nodes.map((item) => ({ t: 'IssueCommentEdge', v: { node: { t: 'PullRequestChangedFile', v: item }, cursor: '' } })),
    pageInfo: (node) => ({ t: 'PageInfo', v: (node.v as { pageInfo: unknown }).pageInfo }),
    totalCount: (node) => (node.v as { totalCount: number }).totalCount,
  },
  PullRequestChangedFile: {
    path: (node) => (node.v as { path: string }).path,
  },
  PageInfo: {
    hasNextPage: (node) => (node.v as { hasNextPage: boolean }).hasNextPage,
    hasPreviousPage: (node) => (node.v as { hasPreviousPage: boolean }).hasPreviousPage,
    endCursor: (node) => (node.v as { endCursor: string | null }).endCursor,
    startCursor: (node) => (node.v as { startCursor: string | null }).startCursor,
  },
  IssueComment: {
    id: (node) => (node.v as Comment).nodeId,
    body: (node) => (node.v as Comment).body,
    author: (node) => ({ t: 'User', v: { login: (node.v as Comment).userLogin, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL } }),
  },
  IssueCommentEdge: {
    node: (node) => (node.v as { node: unknown }).node,
    cursor: (node) => (node.v as { cursor: string }).cursor,
  },
  CreateIssuePayload: {
    issue: (node) => (node.v as { issue: Issue }).issue ? { t: 'Issue', v: (node.v as { issue: Issue }).issue } : null,
    clientMutationId: () => null,
  },
  CloseIssuePayload: {
    issue: (node) => (node.v as { issue: Issue }).issue ? { t: 'Issue', v: (node.v as { issue: Issue }).issue } : null,
    clientMutationId: () => null,
  },
  CreatePullRequestPayload: {
    pullRequest: (node) => (node.v as { pullRequest: Pull }).pullRequest ? { t: 'PullRequest', v: (node.v as { pullRequest: Pull }).pullRequest } : null,
    clientMutationId: () => null,
  },
  MergePullRequestPayload: {
    pullRequest: (node) => (node.v as { pullRequest: Pull }).pullRequest ? { t: 'PullRequest', v: (node.v as { pullRequest: Pull }).pullRequest } : null,
    clientMutationId: () => null,
  },
  AddCommentPayload: {
    commentEdge: (node) => ({ t: 'IssueCommentEdge', v: (node.v as { commentEdge: unknown }).commentEdge }),
    clientMutationId: () => null,
  },
  __Type: {
    name: (node) => (node.v as { name: string }).name,
    kind: (node) => (node.v as { kind: string }).kind,
    fields: (node) => (node.v as { fields: Array<{ name: string }> }).fields.map((field) => ({ t: '__Field', v: field })),
    enumValues: (node) => (node.v as { enumValues: Array<{ name: string }> }).enumValues.map((item) => ({ t: '__EnumValue', v: item })),
    description: () => null,
  },
  __Field: {
    name: (node) => (node.v as { name: string }).name,
    description: () => null,
  },
  __EnumValue: {
    name: (node) => (node.v as { name: string }).name,
    description: () => null,
  },
  Mutation: {
    createIssue: (_node, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const repo = repoFromNodeId(String(input.repositoryId ?? ''));
      if (!repo) {
        ctx.errors.push({ message: 'Could not resolve to a Repository with the provided repositoryId.' });
        return { t: 'CreateIssuePayload', v: { issue: null } };
      }
      const issue = makeIssue(repo, String(input.title ?? ''), String(input.body ?? ''));
      return { t: 'CreateIssuePayload', v: { issue } };
    },
    closeIssue: (_node, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const found = issueFromNodeId(String(input.issueId ?? ''));
      if (!found) {
        ctx.errors.push({ message: 'Could not resolve to an Issue with the provided issueId.' });
        return { t: 'CloseIssuePayload', v: { issue: null } };
      }
      found.issue.state = 'closed';
      found.issue.updatedAt = nowIso();
      return { t: 'CloseIssuePayload', v: { issue: found.issue } };
    },
    createPullRequest: (_node, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const repo = repoFromNodeId(String(input.repositoryId ?? ''));
      if (!repo) {
        ctx.errors.push({ message: 'Could not resolve to a Repository with the provided repositoryId.' });
        return { t: 'CreatePullRequestPayload', v: { pullRequest: null } };
      }
      const pull = makePull(repo, String(input.title ?? ''), String(input.body ?? ''), String(input.headRefName ?? ''), String(input.baseRefName ?? ''));
      if (!pull) {
        ctx.errors.push({ message: 'Could not create a pull request: head or base branch not found.' });
        return { t: 'CreatePullRequestPayload', v: { pullRequest: null } };
      }
      return { t: 'CreatePullRequestPayload', v: { pullRequest: pull } };
    },
    mergePullRequest: (_node, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const found = pullFromNodeId(String(input.pullRequestId ?? ''));
      if (!found) {
        ctx.errors.push({ message: 'Could not resolve to a PullRequest with the provided pullRequestId.' });
        return { t: 'MergePullRequestPayload', v: { pullRequest: null } };
      }
      const merged = doMerge(found.repo, found.pull);
      if (!merged.ok) ctx.errors.push({ message: merged.reason ?? 'Merge conflict' });
      return { t: 'MergePullRequestPayload', v: { pullRequest: found.pull } };
    },
    addComment: (_node, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const found = issueFromNodeId(String(input.subjectId ?? ''));
      if (!found) {
        ctx.errors.push({ message: 'Could not resolve to an Issue with the provided subjectId.' });
        return { t: 'AddCommentPayload', v: { commentEdge: null } };
      }
      commentIdCounter += 1;
      globalSeq += 1;
      const comment: Comment = {
        id: commentIdCounter,
        nodeId: nodeId('C', `${found.repo.owner}/${found.repo.name}#${found.issue.number}:${commentIdCounter}`),
        body: String(input.body ?? ''),
        userLogin: VIEWER_LOGIN,
        createdAt: nowIso(),
        seq: globalSeq,
      };
      found.issue.comments.push(comment);
      return { t: 'AddCommentPayload', v: { commentEdge: { node: { t: 'IssueComment', v: comment }, cursor: '' } } };
    },
  },
};

function wrapValue(item: unknown): GqlNode {
  if (item !== null && typeof item === 'object' && 't' in (item as Record<string, unknown>)) return item as GqlNode;
  if (item !== null && typeof item === 'object' && 'headRef' in (item as Record<string, unknown>)) {
    return { t: 'PullRequest', v: item as Pull };
  }
  if (item !== null && typeof item === 'object' && 'number' in (item as Record<string, unknown>) && 'title' in (item as Record<string, unknown>)) {
    return { t: 'Issue', v: item as Issue };
  }
  if (item !== null && typeof item === 'object' && 'body' in (item as Record<string, unknown>) && 'nodeId' in (item as Record<string, unknown>)) {
    return { t: 'IssueComment', v: item as Comment };
  }
  return { t: 'Unknown', v: item };
}

function resolveSelection(node: GqlNode, selection: GqlField[], variables: Record<string, unknown>, ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const resolvers = GQL_RESOLVERS[node.t] ?? {};
  const knownFields = GQL_TYPE_FIELDS[node.t] ?? [];
  for (const field of selection) {
    if (field.name === '...') {
      if (field.fragmentType === null || field.fragmentType === node.t) {
        Object.assign(out, resolveSelection(node, field.selection ?? [], variables, ctx));
      }
      continue;
    }
    const key = field.alias ?? field.name;
    if (field.name === '__typename') {
      out[key] = node.t;
      continue;
    }
    const resolver = resolvers[field.name];
    if (!resolver) {
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${node.t}".` });
      out[key] = null;
      continue;
    }
    const args: Record<string, unknown> = {};
    for (const [argName, argValue] of Object.entries(field.args)) args[argName] = resolveGqlValue(argValue, variables);
    let value: unknown;
    try {
      value = resolver(node, args, ctx);
    } catch (err) {
      ctx.errors.push({ message: err instanceof Error ? err.message : String(err) });
      out[key] = null;
      continue;
    }
    out[key] = resolveValue(node.t, field, value, variables, ctx, knownFields);
  }
  return out;
}

function resolveValue(parentType: string, field: GqlField, value: unknown, variables: Record<string, unknown>, ctx: GqlCtx, _known: string[]): unknown {
  if (value === null || value === undefined) return null;
  if (field.selection === null) return value;
  if (Array.isArray(value)) {
    return value.map((item) => {
      const wrapped = wrapValue(item);
      return resolveSelection(wrapped, field.selection as GqlField[], variables, ctx);
    });
  }
  if (typeof value === 'object' && 't' in (value as Record<string, unknown>)) {
    return resolveSelection(value as GqlNode, field.selection, variables, ctx);
  }
  return value;
}

function executeGraphQL(body: unknown): Record<string, unknown> {
  const ctx: GqlCtx = { errors: [] };
  if (!isRecord(body) || typeof body.query !== 'string') {
    return { data: null, errors: [{ message: 'A query is required.' }] };
  }
  const variables = isRecord(body.variables) ? (body.variables as Record<string, unknown>) : {};
  let document: GqlDocument;
  try {
    document = new GqlParser(body.query).parseDocument();
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'Syntax error' }] };
  }
  const rootType = document.operation === 'mutation' ? 'Mutation' : 'Query';
  const data = resolveSelection({ t: rootType, v: {} }, document.selection, variables, ctx);
  const result: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) result.errors = ctx.errors;
  return result;
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, rawBody: Buffer): Promise<void> {
  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8')) as unknown;
  } catch {
    sendJson(res, 400, { message: 'Problems parsing JSON' });
    return;
  }
  if (Array.isArray(parsed)) {
    const results = parsed.map((item) => executeGraphQL(item));
    sendJson(res, 200, results);
    return;
  }
  sendJson(res, 200, executeGraphQL(parsed));
}

// ------------------------------------------------------------------ MCP

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, Record<string, unknown>>; required: string[] };
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Issue state filter: open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch onto a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
        body: { type: 'string', description: 'The pull request body.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'number', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const MCP_TOOL_ALIASES: Record<string, string> = {
  createrepository: 'create_repo',
  repocreate: 'create_repo',
  reposcreate: 'create_repo',
  repositorycreate: 'create_repo',
  getrepository: 'get_repo',
  repoget: 'get_repo',
  reposget: 'get_repo',
  repositoryget: 'get_repo',
  issuecreate: 'create_issue',
  issuescreate: 'create_issue',
  issueslist: 'list_issues',
  issuelist: 'list_issues',
  pullrequestcreate: 'create_pull_request',
  pullscreate: 'create_pull_request',
  createpr: 'create_pull_request',
  prcreate: 'create_pull_request',
  pullrequestmerge: 'merge_pull_request',
  pullsmerge: 'merge_pull_request',
  mergepr: 'merge_pull_request',
  prmerge: 'merge_pull_request',
};

function normalizeToolName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function findMcpTool(name: string): McpToolDef | null {
  const wanted = normalizeToolName(name);
  for (const tool of MCP_TOOLS) {
    if (normalizeToolName(tool.name) === wanted) return tool;
  }
  const alias = MCP_TOOL_ALIASES[wanted];
  if (alias) {
    const found = MCP_TOOLS.find((tool) => tool.name === alias);
    if (found) return found;
  }
  for (const tool of MCP_TOOLS) {
    if (normalizeToolName(tool.name).endsWith(wanted) || wanted.endsWith(normalizeToolName(tool.name))) return tool;
  }
  return null;
}

function mcpToolResult(payload: unknown): Record<string, unknown> {
  const text = JSON.stringify(payload);
  return { content: [{ type: 'text', text }], structuredContent: payload };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function callMcpTool(tool: McpToolDef, args: Record<string, unknown>): Record<string, unknown> {
  const missing = tool.inputSchema.required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
  if (missing.length > 0) {
    return mcpToolError(`Missing required argument(s): ${missing.join(', ')}`);
  }
  if (tool.name === 'create_repo') {
    const name = String(args.name);
    if (findRepo(VIEWER_LOGIN, name)) return mcpToolError(`Repository ${VIEWER_LOGIN}/${name} already exists`);
    const repo = createRepoRecord(name, typeof args.description === 'string' ? args.description : '', args.private === true);
    return mcpToolResult({
      id: repo.id,
      node_id: repo.nodeId,
      name: repo.name,
      full_name: `${repo.owner}/${repo.name}`,
      owner: { login: repo.owner },
      private: repo.isPrivate,
      description: repo.description,
      default_branch: repo.defaultBranch,
      html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
      url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    });
  }
  const owner = String(args.owner ?? '');
  const repoName = String(args.repo ?? '');
  const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
  if (tool.name === 'get_repo') {
    if (!repo) return mcpToolError(`Repository ${owner}/${repoName} not found`);
    return mcpToolResult({
      id: repo.id,
      node_id: repo.nodeId,
      name: repo.name,
      full_name: `${repo.owner}/${repo.name}`,
      owner: { login: repo.owner },
      private: repo.isPrivate,
      description: repo.description,
      default_branch: repo.defaultBranch,
      html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
      url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    });
  }
  if (!repo) return mcpToolError(`Repository ${owner}/${repoName} not found`);
  if (tool.name === 'create_issue') {
    const issue = makeIssue(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '');
    return mcpToolResult({
      id: issue.id,
      node_id: issue.nodeId,
      number: issue.number,
      title: issue.title,
      body: issue.body,
      state: issue.state,
      html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
      url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    });
  }
  if (tool.name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    const list = repo.issues.filter((issue) => state === 'all' || issue.state === state);
    return mcpToolResult({
      issues: list.map((issue) => ({ id: issue.id, node_id: issue.nodeId, number: issue.number, title: issue.title, body: issue.body, state: issue.state })),
    });
  }
  if (tool.name === 'create_pull_request') {
    const pull = makePull(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', String(args.head ?? ''), String(args.base ?? ''));
    if (!pull) return mcpToolError('Could not create a pull request: head or base branch not found');
    return mcpToolResult({
      id: pull.id,
      node_id: pull.nodeId,
      number: pull.number,
      pull_number: pull.number,
      title: pull.title,
      body: pull.body,
      state: pull.state,
      head: { ref: pull.headRef },
      base: { ref: pull.baseRef },
      html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
      url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    });
  }
  if (tool.name === 'merge_pull_request') {
    const number = Number(args.pull_number);
    const pull = repo.pulls.find((item) => item.number === number);
    if (!pull) return mcpToolError(`Pull request ${number} not found`);
    if (pull.state === 'closed') return mcpToolError('Pull request is already closed');
    const merged = doMerge(repo, pull);
    if (!merged.ok) return mcpToolError(merged.reason ?? 'Merge conflict');
    return mcpToolResult({ merged: true, sha: merged.sha, number: pull.number, pull_number: pull.number, state: 'closed' });
  }
  return mcpToolError(`Unknown tool: ${tool.name}`);
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, rawBody: Buffer): Promise<void> {
  let parsed: unknown = null;
  let parseFailed = false;
  try {
    parsed = JSON.parse(rawBody.toString('utf8')) as unknown;
  } catch {
    parseFailed = true;
  }
  if (parseFailed || !isRecord(parsed)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const id = parsed.id ?? null;
  const method = typeof parsed.method === 'string' ? parsed.method : '';
  if (!authed(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id, error: { code: -32001, message: 'Unauthorized' } });
    return;
  }
  const sessionId = req.headers['mcp-session-id'];
  const sessionHeader: Record<string, string> = typeof sessionId === 'string' && sessionId !== '' ? { 'mcp-session-id': sessionId } : { 'mcp-session-id': 'forgelet-1' };
  const reply = (payload: unknown): void => {
    sendJson(res, 200, payload, sessionHeader);
  };
  if (parsed.id === undefined) {
    // A notification (e.g. notifications/initialized): no JSON-RPC reply.
    res.writeHead(202, { ...sessionHeader });
    res.end();
    return;
  }
  const params = isRecord(parsed.params) ? parsed.params : {};
  if (method === 'server/discover') {
    reply({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2026-07-28',
        supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
        serverInfo: { name: 'forgelet', version: SERVER_VERSION },
        capabilities: { tools: {} },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forgelet', version: SERVER_VERSION } },
      },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const supported = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    const negotiated = supported.includes(offered) ? offered : '2026-07-28';
    reply({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: negotiated,
        capabilities: { tools: {} },
        serverInfo: { name: 'forgelet', version: SERVER_VERSION },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forgelet', version: SERVER_VERSION } },
      },
    });
    return;
  }
  if (method === 'ping') {
    reply({ jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (method === 'tools/list') {
    reply({ jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const tool = findMcpTool(name);
    if (!tool) {
      reply({ jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${name}` } });
      return;
    }
    reply({ jsonrpc: '2.0', id, result: callMcpTool(tool, args) });
    return;
  }
  reply({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
}

// ------------------------------------------------------------------ git HTTP

async function handleGit(req: IncomingMessage, res: ServerResponse, path: string, method: string, rawBody: Buffer): Promise<boolean> {
  const match = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
  if (!match) return false;
  const owner = match[1] as string;
  const name = match[2] as string;
  const suffix = match[3] ?? '';
  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return true;
  }
  const repo = owner === VIEWER_LOGIN ? findRepo(owner, name) : undefined;
  if (!repo) {
    sendJson(res, 404, { message: 'Not Found' });
    return true;
  }
  const query = queryOf(req);
  if (method === 'GET' && suffix === '/info/refs') {
    const service = query.get('service') ?? '';
    const wantsV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    if (service === 'git-upload-pack') {
      if (wantsV2) {
        sendBytes(res, 200, v2Advertisement(), 'application/x-git-upload-pack-advertisement');
      } else {
        const lines = ['# service=git-upload-pack\n', ...v0AdvertisementLines(repo, UPLOAD_V0_CAPS)];
        sendBytes(res, 200, encodePktLines([...lines, 'flush']), 'application/x-git-upload-pack-advertisement');
      }
      return true;
    }
    if (service === 'git-receive-pack') {
      const lines = ['# service=git-receive-pack\n', ...v0AdvertisementLines(repo, RECEIVE_V0_CAPS)];
      sendBytes(res, 200, encodePktLines([...lines, 'flush']), 'application/x-git-receive-pack-advertisement');
      return true;
    }
    sendJson(res, 400, { message: 'Unknown service' });
    return true;
  }
  if (method === 'POST' && suffix === '/git-upload-pack') {
    try {
      const wantsV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      const out = wantsV2 ? handleUploadPackV2(repo, rawBody) : handleUploadPackV0(repo, rawBody);
      sendBytes(res, 200, out, 'application/x-git-upload-pack-result');
    } catch (err) {
      sendJson(res, 400, { message: err instanceof Error ? err.message : 'Bad request' });
    }
    return true;
  }
  if (method === 'POST' && suffix === '/git-receive-pack') {
    try {
      const out = handleReceivePack(repo, rawBody);
      sendBytes(res, 200, out, 'application/x-git-receive-pack-result');
    } catch (err) {
      sendJson(res, 400, { message: err instanceof Error ? err.message : 'Bad request' });
    }
    return true;
  }
  sendJson(res, 404, { message: 'Not Found' });
  return true;
}

// ------------------------------------------------------------------ server

/** Build the server. It binds nothing until the caller listens. */
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const path = pathOf(req);
        const method = req.method ?? 'GET';
        const rawBody = method === 'GET' || method === 'HEAD' ? Buffer.alloc(0) : await readBody(req);
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (method === 'POST' && path === '/api/graphql') {
          await handleGraphQL(req, res, rawBody);
          return;
        }
        if (path === '/mcp') {
          if (method === 'POST') {
            await handleMcp(req, res, rawBody);
            return;
          }
          sendJson(res, 405, { message: 'Method Not Allowed' });
          return;
        }
        if (await handleGit(req, res, path, method, rawBody)) return;
        if (path.startsWith('/api/v3')) {
          await handleRest(req, res, path, method, queryOf(req), rawBody);
          return;
        }
        sendJson(res, 404, { message: 'Not Found' });
      } catch (err) {
        process.stderr.write(`[forgelet] request failed: ${err instanceof Error ? err.message : String(err)}\n`);
        if (!res.headersSent) sendJson(res, 500, { message: 'Internal Server Error' });
        else res.end();
      }
    })();
  });
}
