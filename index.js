import cookieParser from "cookie-parser";
import express from "express";
import httpCode from "http-status-codes";
import dotenv from "dotenv";
import mysql from "mysql2";
import jwt from "jsonwebtoken";
import * as uuid from "uuid";
import bcrypt from "bcrypt";
import { serialize } from "cookie";

// initialization
dotenv.config();
const app = express();
const port = 8000;
const db = mysql.createConnection({
  host: process.env.MYSQL_HOST,
  port: process.env.MYSQL_PORT,
  user: process.env.MYSQL_USERNAME,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
});

// utils
function createResponse(status, data, error) {
  return {
    meta: { code: status, message: httpCode.getStatusText(status) },
    data: data,
    error: error,
  };
}

async function createJwtTokenClaim(userID, userEmail) {
  const payload = { jti: userID, email: userEmail };
  const token = await jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: 60 * 60 * 24 * 30,
  });
  return token;
}

// middlewares
app.use(cookieParser());
app.use(express.json());

// endpoints
app.get("/", (req, res) => {
  res.status(200).send(createResponse(200, { greet: "Hello" }));
});

app.post("/auth/sign-up", async (req, res) => {
  let error = {};

  if (!req.body.email)
    error.email = [...(error.email ?? []), "email can't be empty"];
  if (!req.body.password)
    error.password = [...(error.password ?? []), "password can't be empty"];
  if (!req.body.password_confirmation)
    error.password_confirmation = [
      ...(error.password_confirmation ?? []),
      "password must be confirmed",
    ];
  if (req.body.password !== req.body.password_confirmation)
    error.password_confirmation = [
      ...(error.password_confirmation ?? []),
      "password confirmation didn't match",
    ];

  if (error.email || error.password || error.password_confirmation)
    return res.status(400).send(createResponse(400, null, error));

  const userID = uuid.v4();
  const passwordSalt = 10;
  const hashedPassword = await bcrypt.hash(req.body.password, passwordSalt);

  db.execute(
    "SELECT id FROM `users` WHERE email = ?",
    [req.body.email],
    (_, results) => {
      if (results.length)
        return res.status(400).json(
          createResponse(400, null, {
            email: [...(error.email ?? []), "email is already signed up"],
          })
        );

      db.execute("INSERT INTO `users` (id, email, password) VALUES (?, ?, ?)", [
        userID,
        req.body.email,
        hashedPassword,
      ]);
      return;
    }
  );

  const jwtToken = await createJwtTokenClaim(userID, req.body.email);
  const serializedCookie = serialize("token", jwtToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 60 * 60 * 24 * 30,
    path: "/",
  });

  res.setHeader("Set-Cookie", serializedCookie);
  res
    .status(201)
    .json(
      createResponse(
        201,
        { user_id: userID, email: req.body.email, token: jwtToken },
        null
      )
    );
});

app.post("/auth/sign-in", async (req, res) => {
  let error = {};

  if (!req.body.email)
    error.email = [...(error.email ?? []), "email can't be empty"];
  if (!req.body.password)
    error.password = [...(error.password ?? []), "password can't be empty"];

  if (error.email || error.password)
    return res.status(400).send(createResponse(400, null, error));

  const [records, fields] = await db
    .promise()
    .execute("SELECT id, email, password FROM `users` WHERE email = ?", [
      req.body.email,
    ]);

  if (!records.length)
    return res.status(400).json(
      createResponse(400, null, {
        email: [...(error.email ?? []), "no account was use this email"],
      })
    );

  const isPasswordMatched = await bcrypt.compare(
    req.body.password,
    records[0].password
  );

  if (!isPasswordMatched) {
    return res.status(401).send(
      createResponse(401, null, {
        password: [...(error.password ?? []), "password didn't match"],
      })
    );
  }

  const jwtToken = await createJwtTokenClaim(records[0].id, records[0].email);
  const serializedCookie = serialize("token", jwtToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 60 * 60 * 24 * 30,
    path: "/",
  });

  res.setHeader("Set-Cookie", serializedCookie);
  res
    .status(201)
    .json(
      createResponse(
        201,
        { user_id: records[0].id, email: records[0].email, token: jwtToken },
        null
      )
    );
});

async function authorize(req, res, next) {
  const { cookies } = req;

  const token = cookies.token;
  if (!token) {
    res.status(401).send(createResponse(401, null, null));
    return;
  }

  const isJWTValid = await jwt.verify(token, process.env.JWT_SECRET);

  if (!isJWTValid) {
    res.status(401).send(createResponse(401, null, null));
    return;
  }

  next();
}

app.get("/auth/sign-out", authorize, (req, res) => {
  const serialized = serialize("token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: -1,
    path: "/",
  });
  res.setHeader("Set-Cookie", serialized);
  res.status(200).json(createResponse(200, null, null));
});

app.get("/labels", authorize, async (req, res) => {
  const jwtToken = req.cookies.token;
  const claims = jwt.decode(jwtToken);

  const [results] = await db
    .promise()
    .execute("SELECT id, title, color FROM labels WHERE user_id = ?", [
      claims.jti,
    ]);

  res.status(200).json(createResponse(200, results, null));
});

app.post("/labels", authorize, async (req, res) => {
  const jwtToken = req.cookies.token;
  const claims = jwt.decode(jwtToken);
  const labelID = uuid.v4();

  const [] = await db
    .promise()
    .execute(
      "INSERT INTO labels (id, user_id, title, color) VALUES (?, ?, ?, ?)",
      [labelID, claims.jti, req.body.title, req.body.color]
    );

  res.status(201).json(createResponse(201, { id: labelID }, null));
});

app.get("/labels/:label_id", authorize, async (req, res) => {
  const jwtToken = req.cookies.token;
  const claims = jwt.decode(jwtToken);
  const labelID = req.params.label_id;

  const [results] = await db
    .promise()
    .execute(
      "SELECT id, title, color FROM labels WHERE user_id = ? and id = ?",
      [claims.jti, labelID]
    );

  if (!results.length) {
    res.status(404).json(createResponse(404, null, null));
    return;
  }

  res.status(200).json(createResponse(200, results, null));
});

app.put("/labels/:label_id", authorize, async (req, res) => {
  const labelID = req.params.label_id;

  const [results] = await db
    .promise()
    .execute("UPDATE labels SET title = ?, color = ? WHERE id = ?", [
      req.body.title,
      req.body.color,
      labelID,
    ]);

  if (!results.changedRows) {
    res.status(404).json(createResponse(404, null, null));
    return;
  }

  res.status(204).send();
});

app.delete("/labels/:label_id", authorize, async (req, res) => {
  const labelID = req.params.label_id;

  const [results] = await db
    .promise()
    .execute("DELETE FROM labels WHERE id = ?", [labelID]);

  if (!results.changedRows) {
    res.status(404).json(createResponse(404, null, null));
    return;
  }

  res.status(204).send();
});

// launcher
app.listen(port, function () {
  console.log(`running server from port ${port}`);
});
