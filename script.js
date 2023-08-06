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
});

const User = mongoose.model("User", userSchema);//User naam ka model bana do userSchema ke hisab se

const app = express();

// Using Middlewares
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Setting up View Engine
app.set("view engine", "ejs");

const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;
  // console.log(req.cookies);
  if (token) {
    const decoded = jwt.verify(token, "sdjasdbajsdbjasds");

    req.user = await User.findById(decoded._id);

    next();
  } else {
    res.redirect("/login");
  }
};
//params(path, middleware, arrow function)
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

  const token = jwt.sign({ _id: user._id }, "sdjasdbajsdbjasds");//

  //params(name of the cookie, name of the token, props of this cookie)
  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60*60 * 1000),//this cookies life= 1 min
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

  const token = jwt.sign({ _id: user._id }, "sdjasdbajsdbjas");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60*60 * 1000),
  });
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

app.listen(5000, () => {
  console.log(`Server is working on port : http://localhost:${5000}/register`);
});

