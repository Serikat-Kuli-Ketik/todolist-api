import express from "express";
import HTTP_STATUS_CODES from "http-status-enum";
import dotenv from "dotenv";

// initialization
dotenv.config();
const app = express();
const port = 8000;

// utils
function createResponse(status, data, error) {
  return {
    meta: { code: status, message: HTTP_STATUS_CODES[status] },
    data: data,
    error: error,
  };
}

// endpoints
app.get("/", (req, res) => {
  res
    .status(200)
    .send(createResponse(200, { greet: process.env.MYSQL_USERNAME }));
});

// launcher
app.listen(port, function () {
  console.log(`running server from port ${port}`);
});
