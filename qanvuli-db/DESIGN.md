# DB Design

SQLite 3で動作する前提とする。

## 

```mermaid

erDiagram
  users {
    uuid char(32) PK
    name varchar(11)
    created_at timestamp
    updated_at timestamp
    deleted_at timestamp
    published_at
}

```

