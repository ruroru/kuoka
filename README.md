# kuoka
kuoka is a  webdav handler for clojure ring
## Install

```clojure
[org.clojars.jj/kuoka "0.1.0-SNAPSHOT"]
```

## Quick start

```clojure
(require '[jj.kuoka.core :as srv])

;; Create a Ring handler with defaults (./webdav-data)
(def app (srv/make-handler :admin-password "s3cret"))

;; With custom config + extra users
(def app (srv/make-handler "/var/webdav" "s3cret" {"alice" "p4ss" "bob" "b0b123"}))

;; Use with any Ring-compatible server:

;; ring-http-exchange (JDK built-in, no extra deps)
(require '[ring-http-exchange.core :as http])
(def server (http/run-http-server app {:port 8080}))
(.stop server 0)

;; Jetty
(require '[ring.adapter.jetty :as jetty])
(def server (jetty/run-jetty app {:port 8080 :join? false}))
(.stop server)

;; http-kit
(require '[org.httpkit.server :as hk])
(def stop-fn (hk/run-server app {:port 8080}))
(stop-fn)
```

## User isolation

Every user gets a home directory created automatically at `/<username>/` on the filesystem. All requests are scoped to the user's home:

- `admin` requesting `PUT /hello.txt` writes to `<root>/admin/hello.txt`
- `alice` requesting `PUT /hello.txt` writes to `<root>/alice/hello.txt`
- `admin` requesting `GET /hello.txt` reads `<root>/admin/hello.txt`

Users cannot access each other's directories. Admin has access to all home directories.

## Authentication

HTTP Basic Auth is required for all methods except OPTIONS. Unauthenticated requests get `401` with `WWW-Authenticate: Basic`.

```clojure
(require '[jj.kuoka.handler :as h])

;; Create state manually for full control
(def st (h/init-state "webdav-data" :admin-password "s3cret"))

;; Add a user (creates home directory + ACL automatically)
(h/add-user st "carol" "p4ssw0rd" :displayname "Carol")

;; Build ring handler
(def app (h/make-app st))
```

## File operations

All examples use `admin:admin` credentials. Paths are relative to the user's home directory.

### PUT — create/update a file

```bash
curl -u admin:admin -X PUT http://localhost:8080/hello.txt -d "Hello WebDAV"
# Writes to <root>/admin/hello.txt
```

### GET — read a file

```bash
curl -u admin:admin http://localhost:8080/hello.txt
```

### DELETE — remove a file

```bash
curl -u admin:admin -X DELETE http://localhost:8080/hello.txt
```

### MKCOL — create a directory

```bash
curl -u admin:admin -X MKCOL http://localhost:8080/docs/
# Creates <root>/admin/docs/
```

### HEAD — get headers only

```bash
curl -u admin:admin -I http://localhost:8080/hello.txt
```

### OPTIONS — discover capabilities

```bash
curl -X OPTIONS http://localhost:8080/
# No auth required
# Response headers: DAV: 1, 2, access-control
#                   Allow: GET, PUT, DELETE, PROPFIND, ...
```

## Access control (ACL)

Every resource has an ACL (Access Control List) made of ACEs (Access Control Entries). Each ACE grants or denies privileges to a principal.

Home directories are created with an ACL granting the owner full access and admin full access. New files inherit their parent directory's ACL.

### Read the ACL

```bash
curl -u admin:admin -X PROPFIND http://localhost:8080/hello.txt \
  -H "Depth: 0" -H "Content-Type: application/xml" \
  -d '<D:propfind xmlns:D="DAV:"><D:prop><D:acl/></D:prop></D:propfind>'
```

### Set the ACL

```bash
curl -u admin:admin -X ACL http://localhost:8080/hello.txt \
  -H "Content-Type: application/xml" \
  -d '<D:acl xmlns:D="DAV:">
        <D:ace>
          <D:principal><D:href>/_principals/admin</D:href></D:principal>
          <D:grant>
            <D:privilege><D:read/></D:privilege>
            <D:privilege><D:write-content/></D:privilege>
            <D:privilege><D:write-acl/></D:privilege>
          </D:grant>
        </D:ace>
      </D:acl>'
```

### ACL evaluation rules

Per RFC 3744 Section 6:

1. ACEs are evaluated in order
2. A matching **deny** ACE for an ungranted required privilege causes immediate denial
3. **Grant** ACEs accumulate privileges
4. When all required privileges are granted, access is allowed
5. If ACEs are exhausted without granting all required privileges, access is denied

### Privileges

| Privilege | Controls | Abstract? |
|-----------|----------|-----------|
| `all` | All operations | Yes — cannot be set in ACEs |
| `read` | GET, HEAD, OPTIONS, PROPFIND | No |
| `write` | Aggregate of write-content, write-properties, bind, unbind | Yes |
| `write-content` | PUT on existing resources | No |
| `write-properties` | PROPPATCH | No |
| `bind` | PUT new file, MKCOL | No |
| `unbind` | DELETE | No |
| `read-acl` | PROPFIND for DAV:acl | No |
| `write-acl` | ACL method | No |
| `read-current-user-privilege-set` | PROPFIND for current-user-privilege-set | No |
| `unlock` | UNLOCK by non-owner | No |

Abstract privileges cannot appear in ACE `grant`/`deny` elements. They exist only in the privilege tree for organizational purposes.

## Properties (PROPFIND / PROPPATCH)

### Read properties

```bash
# All properties
curl -u admin:admin -X PROPFIND http://localhost:8080/hello.txt \
  -H "Depth: 0" -H "Content-Type: application/xml" \
  -d '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'

# Specific properties
curl -u admin:admin -X PROPFIND http://localhost:8080/hello.txt \
  -H "Depth: 0" -H "Content-Type: application/xml" \
  -d '<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/><D:getcontentlength/></D:prop></D:propfind>'

# Depth 1 (collection members)
curl -u admin:admin -X PROPFIND http://localhost:8080/docs/ \
  -H "Depth: 1" -H "Content-Type: application/xml" \
  -d '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
```

### Write dead properties

```bash
curl -u admin:admin -X PROPPATCH http://localhost:8080/hello.txt \
  -H "Content-Type: application/xml" \
  -d '<D:propertyupdate xmlns:D="DAV:">
        <D:set><D:prop><D:displayname>Greeting</D:displayname></D:prop></D:set>
      </D:propertyupdate>'
```

Live properties (`getcontentlength`, `resourcetype`, `acl`, etc.) are protected — attempts to modify them return `403 Forbidden` in the Multi-Status response.

## Locking

### LOCK

```bash
curl -u admin:admin -X LOCK http://localhost:8080/hello.txt \
  -H "Content-Type: application/xml" \
  -d '<D:lockinfo xmlns:D="DAV:">
        <D:lockscope><D:exclusive/></D:lockscope>
        <D:locktype><D:write/></D:locktype>
      </D:lockinfo>'
# Response includes Lock-Token header and lockdiscovery XML body
```

A lock prevents non-owners from modifying the ACL on the locked resource. The lock owner can always modify the ACL.

### UNLOCK

```bash
curl -u admin:admin -X UNLOCK http://localhost:8080/hello.txt \
  -H "Lock-Token: <opaquelocktoken:uuid-from-lock-response>"
```

## MOVE / COPY

Destination paths are scoped to the user's home directory automatically.

```bash
# Move
curl -u admin:admin -X MOVE http://localhost:8080/old.txt \
  -H "Destination: http://localhost:8080/new.txt"

# Copy
curl -u admin:admin -X COPY http://localhost:8080/src.txt \
  -H "Destination: http://localhost:8080/dst.txt"
```

## Reports

```bash
# Find principals by displayname
curl -u admin:admin -X REPORT http://localhost:8080/ \
  -H "Content-Type: application/xml" -H "Depth: 0" \
  -d '<D:principal-property-search xmlns:D="DAV:">
        <D:property-search><D:prop><D:displayname/></D:prop><D:match>admin</D:match></D:property-search>
        <D:prop><D:displayname/></D:prop>
      </D:principal-property-search>'

# Discover which properties are searchable
curl -u admin:admin -X REPORT http://localhost:8080/ \
  -H "Content-Type: application/xml" \
  -d '<D:principal-search-property-set xmlns:D="DAV:"/>'

# Find current user's principal
curl -u admin:admin -X REPORT http://localhost:8080/ \
  -H "Content-Type: application/xml" -H "Depth: 0" \
  -d '<D:principal-match xmlns:D="DAV:">
        <D:principal-property><D:principal-url/></D:principal-property>
        <D:prop><D:displayname/></D:prop>
      </D:principal-match>'
```

## Error responses

Access denied returns `403` with a `DAV:error` XML body listing which resource and privilege are missing:

```xml
<D:error xmlns:D="DAV:">
  <D:need-privileges>
    <D:resource>
      <D:href>/admin/hello.txt</D:href>
      <D:privilege><D:write-content/></D:privilege>
    </D:resource>
  </D:need-privileges>
</D:error>
```

## Programmatic API

```clojure
(require '[jj.kuoka.handler :as h])

;; Create state atom
(def st (h/init-state "/var/webdav" :admin-password "s3cret"))

;; Add users (creates home directory + ACL automatically)
(h/add-user st "carol" "p4ss" :displayname "Carol")

;; Build ring handler
(def app (h/make-app st))

;; Use with your preferred Ring server adapter
```
