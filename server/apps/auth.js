import { Router } from "express";
import bcrypt from "bcrypt";
import { db } from "../utils/db.js";
import jwt from "jsonwebtoken";

const authRouter = Router();

authRouter.post("/register", async (req, res) => {
  try {
    const { username, password, firstName, lastName } = req.body;

    const collection = db.collection("users");

    // เช็ค username ซ้ำ
    const existingUser = await collection.findOne({ username });
    if (existingUser) {
      return res.status(400).json({
        message: "Username already exists"
      });
    }

    // hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await collection.insertOne({
      username,
      password: hashedPassword,
      firstName,
      lastName
    });

    res.status(201).json({
      message: "User has been created successfully"
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});



// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้

authRouter.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await db.collection("users").findOne({ username });

  //username ไม่ถูก
  if (!user) {
    return res.status(401).json({
      message: "Invalid username or password"
    });
  }

  //password ไม่ถูก
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(401).json({
      message: "Invalid username or password"
    });
  }

  //สร้าง token
  const token = jwt.sign(
    {
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName
    },
    "SECRET_KEY",
    { expiresIn: "1h" }
  );

  res.status(200).json({
    message: "Login successfully",
    token
  });
});


export default authRouter;
