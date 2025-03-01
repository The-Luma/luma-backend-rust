CREATE TABLE "users" (
  "id" SERIAL PRIMARY KEY,
  "username" VARCHAR(50) UNIQUE NOT NULL,
  "email" VARCHAR(255) UNIQUE NOT NULL,
  "password" VARCHAR(255) NOT NULL,
  "created_at" TIMESTAMP NOT NULL
);

CREATE TABLE "document" (
  "id" SERIAL PRIMARY KEY,
  "user_id" SERIAL NOT NULL,
  "title" VARCHAR(255) NOT NULL,
  "content" BYTEA NOT NULL,
  "extracted_text" TEXT,
  "file_metadata" JSONB NOT NULL,
  "type" VARCHAR(50) NOT NULL,
  "upload_at" TIMESTAMP NOT NULL
);

CREATE TABLE "doc_user" (
  "id" Serial PRIMARY KEY,
  "doc_id" SERIAL NOT NULL,
  "user_id" SERIAL NOT NULL,
  "auth" char NOT NULL
);

CREATE TABLE "chats" (
  "id" Serial PRIMARY KEY,
  "user_id" SERIAL NOT NULL,
  "namespace_id" SERIAL NOT NULL,
  "sent_at" TIMESTAMP NOT NULL
);

CREATE TABLE "message" (
  "id" SERIAL PRIMARY KEY,
  "chat_id" SERIAL NOT NULL,
  "user" BINARY NOT NULL,
  "response" TEXT NOT NULL,
  "time_sent" timestamp NOT NULL
);

CREATE TABLE "namespace" (
  "id" SERIAL PRIMARY KEY,
  "user_id" SERIAL NOT NULL,
  "doc_id" SERIAL[] NOT NULL,
  "share" binary NOT NULL
);

CREATE TABLE "namespace_doc" (
  "id" SERIAL PRIMARY KEY,
  "namespace_id" SERIAL NOT NULL,
  "doc_id" SERIAL NOT NULL,
  "vec_id" text[] NOT NULL
);

CREATE TABLE "namespace_auth" (
  "id" SERIAL PRIMARY KEY,
  "user_id" SERIAL NOT NULL,
  "namespace_id" SERIAL NOT NULL,
  "auth_level" SERIAL NOT NULL
);



ALTER TABLE "document" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "doc_user" ADD FOREIGN KEY ("doc_id") REFERENCES "document" ("id");

ALTER TABLE "doc_user" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "message" ADD FOREIGN KEY ("chat_id") REFERENCES "chats" ("id");

ALTER TABLE "chats" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "namespace" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "namespace_doc" ADD FOREIGN KEY ("doc_id") REFERENCES "document" ("id");

ALTER TABLE "namespace_doc" ADD FOREIGN KEY ("namespace_id") REFERENCES "namespace" ("doc_id");

ALTER TABLE "namespace_auth" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "namespace_auth" ADD FOREIGN KEY ("namespace_id") REFERENCES "namespace" ("id");
