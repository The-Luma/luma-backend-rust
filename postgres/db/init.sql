CREATE TABLE "users" (
  "id" SERIAL PRIMARY KEY,
  "username" VARCHAR(50) UNIQUE NOT NULL,
  "email" VARCHAR(255) UNIQUE NOT NULL,
  "password" VARCHAR(255) NOT NULL,
  "role" VARCHAR(20) NOT NULL,
  "created_at" TIMESTAMP NOT NULL DEFAULT (now()),
  "updated_at" TIMESTAMP NOT NULL DEFAULT (now())
);

CREATE TABLE "document" (
  "id" SERIAL PRIMARY KEY,
  "user_id" INT NOT NULL,
  "title" VARCHAR(255) NOT NULL,
  "file_path" TEXT NOT NULL,
  "file_metadata" JSONB NOT NULL,
  "type" VARCHAR(50) NOT NULL,
  "is_public" BOOLEAN NOT NULL DEFAULT true,
  "uploaded_at" TIMESTAMP NOT NULL
);

CREATE TABLE "doc_user" (
  "id" SERIAL PRIMARY KEY,
  "doc_id" INT NOT NULL,
  "user_id" INT NOT NULL,
  "permission" VARCHAR(20) NOT NULL
);

CREATE TABLE "chats" (
  "id" SERIAL PRIMARY KEY,
  "user_id" INT NOT NULL,
  "namespace_id" INT NOT NULL,
  "started_at" TIMESTAMP NOT NULL
);

CREATE TABLE "message" (
  "id" SERIAL PRIMARY KEY,
  "chat_id" INT NOT NULL,
  "sender_type" VARCHAR(10) NOT NULL,
  "content" TEXT NOT NULL,
  "time_sent" TIMESTAMP NOT NULL
);

CREATE TABLE "namespace" (
  "id" SERIAL PRIMARY KEY,
  "user_id" INT NOT NULL,
  "name" VARCHAR(255) NOT NULL,
  "description" TEXT,
  "is_public" BOOLEAN NOT NULL DEFAULT false,
  "created_at" TIMESTAMP NOT NULL DEFAULT (now())
);

CREATE TABLE "namespace_doc" (
  "id" SERIAL PRIMARY KEY,
  "namespace_id" INT NOT NULL,
  "doc_id" INT NOT NULL,
  "vec_id" TEXT[] NOT NULL
);

CREATE TABLE "namespace_auth" (
  "id" SERIAL PRIMARY KEY,
  "user_id" INT NOT NULL,
  "namespace_id" INT NOT NULL,
  "auth_level" INT NOT NULL
);

COMMENT ON COLUMN "users"."role" IS 'e.g., ''admin'' or ''user''';

COMMENT ON COLUMN "document"."user_id" IS 'Owner of the document';

COMMENT ON COLUMN "document"."file_path" IS 'Link to the file on the local system';

COMMENT ON COLUMN "document"."file_metadata" IS 'Additional file details (e.g., file size, original filename)';

COMMENT ON COLUMN "document"."type" IS 'File type, e.g., ''pdf'', ''docx''';

COMMENT ON COLUMN "document"."is_public" IS 'True for public, false for private';

COMMENT ON COLUMN "document"."uploaded_at" IS 'Time of upload';

COMMENT ON COLUMN "doc_user"."permission" IS 'e.g., ''read'' or ''write''';

COMMENT ON COLUMN "chats"."user_id" IS 'Owner of the chat';

COMMENT ON COLUMN "chats"."namespace_id" IS 'Associated namespace for contextual LLM queries';

COMMENT ON COLUMN "chats"."started_at" IS 'Time when the chat was initiated';

COMMENT ON COLUMN "message"."sender_type" IS 'Either ''user'' or ''LLM''';

COMMENT ON COLUMN "namespace"."user_id" IS 'Creator/owner of the namespace';

COMMENT ON COLUMN "namespace"."name" IS 'Name of the namespace';

COMMENT ON COLUMN "namespace"."description" IS 'Optional description';

COMMENT ON COLUMN "namespace"."is_public" IS 'Visibility flag for the namespace';

COMMENT ON COLUMN "namespace_doc"."vec_id" IS 'Corresponding vector record IDs in the vector database';

COMMENT ON COLUMN "namespace_auth"."auth_level" IS 'Permission level within the namespace. 1 represents read-only access, 2 for read and write, and 3 for full administrative privileges (+delete, +share (basically, owner))';

ALTER TABLE "document" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "doc_user" ADD FOREIGN KEY ("doc_id") REFERENCES "document" ("id");

ALTER TABLE "doc_user" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "message" ADD FOREIGN KEY ("chat_id") REFERENCES "chats" ("id");

ALTER TABLE "chats" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "chats" ADD FOREIGN KEY ("namespace_id") REFERENCES "namespace" ("id");

ALTER TABLE "namespace" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "namespace_doc" ADD FOREIGN KEY ("namespace_id") REFERENCES "namespace" ("id");

ALTER TABLE "namespace_doc" ADD FOREIGN KEY ("doc_id") REFERENCES "document" ("id");

ALTER TABLE "namespace_auth" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "namespace_auth" ADD FOREIGN KEY ("namespace_id") REFERENCES "namespace" ("id");
