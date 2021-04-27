/* write your server code here */
require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
// const cors = require("cors");
const USERS = [
  {
    email: "admin@email.com",
    name: "admin",
    password: "$2b$10$7QT3g8m1s925VZyPOa/9f.xjjJR9bq2.m1cm3ev..Yh2ECeNxQFfC",
    isAdmin: true,
  },
  {
    email: "eyal@email.com",
    name: "eyal",
    password: "$2b$10$0T5rL0EnBCeK1hbgOcFAmeYsSIgfmGAPcAk13SQAIlrYteouAubLe",
    isAdmin: false,
  },
];
const bcrypt = require("bcrypt");
const { hashSync, genSaltSync, compareSync } = require("bcrypt");
const { sign } = require("jsonwebtoken");
const app = express();
app.use(express.json());
// app.use(cors());
const INFORMATION = [
  {
    email: "eyal@email.com",
    name: "eyal info",
  },
];
const REFRESHTOKENS = [];

app.post("/users/register", (req, res) => {
  console.log(USERS);
  const body = req.body;
  try {
    body.password = hashSync(body.password, genSaltSync(10));
    if (USERS.length === 0 && body.email === "admin@email.com") {
      body.isAdmin = true;
      USERS.push({
        email: body.email,
        name: body.name,
        password: body.password,
      });
      INFORMATION.push({
        email: `${body.email}`,
        info: `${body.name} info`,
      });
      return res.status(201).json({ message: "Register Success" });
    } else {
      const user = USERS.find((user) => user.email === body.email);
      if (user) {
        return res.status(409).json({ message: "user already exists" });
      } else {
        body.isAdmin = false;
        INFORMATION.push({
          email: `${body.email}`,
          info: `${body.name} info`,
        });
        USERS.push({
          email: body.email,
          name: body.name,
          password: body.password,
          isAdmin: false,
        });
        console.log(USERS);
        return res.status(201).json({ message: "Register Success" });
      }
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/users/login", (req, res) => {
  const body = req.body;
  try {
    const user = USERS.find((user) => user.email === body.email);
    if (!user) {
      return res.status(404).json({ message: "cannot find user" });
    }
    const isPasswordCorrect = compareSync(body.password, user.password);
    if (isPasswordCorrect) {
      body.password = undefined;
      const accessToken = sign({ result: body }, process.env.JWT_CODE, {
        expiresIn: "2h",
      });
      const refreshToken = sign({ result: body }, process.env.JWT_CODE_REFRESH);
      REFRESHTOKENS.push(refreshToken);
      return res.status(200).json({
        refreshToken: refreshToken,
        accessToken: accessToken,
        email: body.email,
        name: user.name,
        isAdmin: user.isAdmin,
      });
    } else {
      return res.status(403).json({ message: "User or Password incorrect" });
    }
  } catch (err) {
    console.log(err);
  }
});
app.post("/users/tokenValidate", (req, res) => {
  let token = req.get("authorization");
  console.log(token);
  if (token) {
    // Remove Bearer from string
    token = token.slice(7);
    console.log(token);
    console.log(process.env.JWT_CODE);
    jwt.verify(token, process.env.JWT_CODE, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: "Invalid Access Token" });
      } else {
        req.decoded = decoded;
        console.log(req.decoded);
        return res.status(200).json({ valid: true });
      }
    });
  } else {
    return res.status(401).json({ message: "Access Token Required" });
  }
});

app.get("/api/v1/information", (req, res) => {
  let token = req.get("authorization");
  if (token) {
    token = token.slice(7);
    jwt.verify(token, process.env.JWT_CODE, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: "Invalid Access Token" });
      } else {
        req.decoded = decoded;
        const pit = INFORMATION.find(
          (user) => user.email === req.decoded.result.email
        );
        return res.status(200).json(pit);
      }
    });
  } else {
    return res.status(401).json({ message: "Access Token Required" });
  }
});

app.post("/users/token", (req, res) => {
  const body = req.body;
  let token = req.get("authorization").slice(7);
  console.log("token:");
  console.log(token);
  const refToken = REFRESHTOKENS.find((rToken) => rToken === body.refreshToken);
  console.log(refToken);
  if (refToken) {
    return res.status(200).json(token);
  } else {
    return res.status(403).json("inValid refresh Token");
  }
});

module.exports = app;
