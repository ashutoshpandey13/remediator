const express = require("express");

const app = express();

app.get("/", (req, res) => {
  res.send("AuDeSec PoC Running");
});

app.get("/health", (req, res) => {
  res.send("OK");
});

app.listen(3000, () => {
  console.log("Server started");
});
