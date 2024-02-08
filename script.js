import express from "express";
import mongoose from "mongoose";
import path from "path";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

mongoose.connect("mongodb://127.0.0.1:27017", {
    dbName: "backend",
  })
  .then(() => console.log("Database Connected"))
  .catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  refreshToken: String 
});

const User = mongoose.model("User", userSchema);


import { generateSecretKey } from "./key.js";
import fs from 'fs';
import dotenv from 'dotenv';
dotenv.config();

const PORT = process.env.PORT


const accessSecret = generateSecretKey();
const refreshSecret = generateSecretKey();

process.env.ACCESS_SECRET = accessSecret;
process.env.REFRESH_SECRET = refreshSecret;

const app = express();

app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.set("view engine", "ejs");

const generateTokens = (user) => {
  const accessToken = jwt.sign({ _id: user._id }, "accessSecret", {
    expiresIn: "1h" 
  });
  const refreshToken = jwt.sign({ _id: user._id }, "refreshSecret", {
    expiresIn: "7d"
  });
  return { accessToken, refreshToken };
};

const isAuthenticated = async (req, res, next) => {
  const { token, refreshToken } = req.cookies;
  
  if (!token && !refreshToken) {
    return res.redirect("/login");
  }

  try {
    if (token) {
      const decoded = jwt.verify(token, "accessSecret");
      req.user = await User.findById(decoded._id);
    } else if (refreshToken) {
      const decoded = jwt.verify(refreshToken, "refreshSecret");
      req.user = await User.findById(decoded._id);
    }

    if (!req.user) {
      throw new Error("User not found");
    }

    next();
  } catch (error) {
    console.error("Invalid token:", error.message);
    res.redirect("/login");
  }
};

app.get("/", isAuthenticated, (req, res) => {
  res.render("logout", { name: req.user.name });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  let user = await User.findOne({ email });

  if (!user) return res.redirect("/register");

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch)
    return res.render("login", { email, message: "Incorrect Password" });

  const { accessToken, refreshToken } = generateTokens(user);

  res.cookie("token", accessToken, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 60 * 1000),
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  res.redirect("/");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  let user = await User.findOne({ email });
  if (user) {
    return res.redirect("/login");
  }
  const hashedPassword = await bcrypt.hash(password, 10);

  user = await User.create({
    name,
    email,
    password: hashedPassword,
  });

  const { accessToken, refreshToken } = generateTokens(user);

  res.cookie("token", accessToken, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 60 * 1000),
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.clearCookie("refreshToken");
  res.redirect("/");
});

app.get("/refresh-token", async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token not found" });
  }

  try {
    const decoded = jwt.verify(refreshToken, "refreshSecret");
    const user = await User.findById(decoded._id);

    if (!user) {
      throw new Error("User not found");
    }

    const { accessToken, newRefreshToken } = generateTokens(user);

    res.cookie("token", accessToken, {
      httpOnly: true,
      expires: new Date(Date.now() + 60 * 60 * 1000),
    });

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    res.status(200).json({ accessToken });
  } catch (error) {
    console.error("Error refreshing token:", error.message);
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

app.listen(5000, () => {
  console.log(`Server is working on port : http://localhost:${PORT}/register`);
});
