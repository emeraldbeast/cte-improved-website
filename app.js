require("dotenv").config();
const express = require('express');
const app = express();
const port = 3000;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const mongoose = require("mongoose");
const User = require('./modules/user');
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});


const JWT_SECRET = process.env.JWT_SECRET;
app.use(express.static('public'));
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Authentication middleware
function isAuthenticated(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect("/login");
  }
}

// Routes
app.get('/', (req, res) => {
  res.render("index");
});

app.get("/signup", (req, res) => {
  res.render("signup", { errorMessage: null });
});

app.get("/login", (req, res) => {
  res.render("login", { errorMessage: null });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

const saltRounds = 10;

app.post("/signup", async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render("signup", { errorMessage: "Passwords do not match" });
  }

  const emailRegex = /^f(2019|2020|2021|2022|2023|2024|2025)\d{4}@goa\.bits-pilani\.ac\.in$/;
  if (!emailRegex.test(email)) {
    return res.render("signup", { errorMessage: "Invalid email format" });
  }

  const existingUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existingUser) {
    return res.render("signup", { errorMessage: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const newUser = new User({ username, email, password: hashedPassword });
  await newUser.save();

  res.redirect("/dashboard");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render("login", { errorMessage: "Invalid credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.render("login", { errorMessage: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "2d" });

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 2 * 24 * 60 * 60 * 1000,
    });

    res.redirect("/dashboard");
  } catch (error) {
    console.error("Login error:", error);
    res.render("login", {
      errorMessage: "Something went wrong. Please try again.",
    });
  }
});

// Dashboard router with nested protection
const dashboardRouter = express.Router();
dashboardRouter.use(isAuthenticated);

dashboardRouter.get("/", async (req, res) => {
  const user = await User.findById(req.user.userId);
  res.render("dashboard", { user });
});

dashboardRouter.get("/courses", async (req, res) => {
  const allCourses = [
    {
      id: "algo",
      title: "Introduction to C++ and Competitive Programming",
      org: "AlgomaniaX"
    },
    {
      id: "devsoc",
      title: "Introduction to Full-Stack App Development",
      org: "DevSoc"
    },
    {
      id: "sofi",
      title: "Investing 101: A Primer on Finance and Investing",
      org: "SoFI"
    },
    {
      id: "bgcc",
      title: "Introduction to Consulting",
      org: "BGCC"
    },
    {
      id: "erc",
      title: "Introduction to Robotics",
      org: "ERC"
    },
    {
      id: "aerod",
      title: "Design, Build and Fly",
      org: "AeroD"
    },
    {
      id: "dwdg",
      title: "Investment Banking - Mergers and Acquisitions",
      org: "DWDG"
    },
    {
      id: "saidl",
      title: "Building LLMs from Scratch",
      org: "SAiDL"
    }
  ];

  // Simulate registered course IDs for the logged-in user
  const registeredCourseIds = ["algo","saidl"]; // Replace with dynamic logic later

  const registeredCourses = allCourses.filter(course => registeredCourseIds.includes(course.id));
  const unregisteredCourses = allCourses.filter(course => !registeredCourseIds.includes(course.id));

  res.render("courses", { registeredCourses, unregisteredCourses });
});


app.use("/dashboard", dashboardRouter);

module.exports = app; 