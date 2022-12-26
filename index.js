import cookieParser from "cookie-parser";
import express from "express";
import HTTP_STATUS_CODES from "http-status-enum";
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
    meta: { code: status, message: HTTP_STATUS_CODES[status] },
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

// launcher
app.listen(port, function () {
  console.log(`running server from port ${port}`);
});
