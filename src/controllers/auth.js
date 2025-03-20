import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { prisma } from "../db.js";
import { createAccessToken } from "../libs/jwt.js";

export const register = async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: passwordHash,
      },
    });

    if (!user) return res.status(500).json({ error: "Email already exists" });

    // Assign role and internal sector to user on register (default values)
    const [role, internalSec] = await prisma.$transaction([
      prisma.role.findFirst({
        where: {
          name: "ejecutor",
        },
      }),
      prisma.internalSec.findFirst({
        where: {
          name: "Guest",
        },
      }),
    ]);

    if (!role || !internalSec)
      return res
        .status(500)
        .json({ error: "Role or Internal Sector not found" });

    await prisma.$transaction([
      prisma.userRole.create({
        data: {
          roleId: role.id,
          userId: user.id,
        },
      }),
      prisma.userInternalSec.create({
        data: {
          internalSecId: internalSec.id,
          userId: user.id,
        },
      }),
    ]);

    const accessToken = await createAccessToken({ id: user.id, username });
    res.cookie("token", accessToken, {
      httpOnly: process.env.NODE_ENV === "production",
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
    });

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: role,
      internalSec: internalSec,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
      include: {
        role: {
          select: {
            role: true,
          },
        },
        internalSec: {
          select: {
            internalSecId: true,
          },
        },
      },
    });

    if (!user) return res.status(404).json({ error: "User not found" });

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword)
      return res.status(401).json({ error: "Invalid password" });

    const accessToken = await createAccessToken({
      id: user.id,
      username: user.username,
      email: user.email,
      internalSec: user.internalSec[0].internalSecId,
      role: user.role.role,
    });

    res.cookie("token", accessToken, {
      httpOnly: process.env.NODE_ENV === "production",
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
    });

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      internalSec: user.internalSec,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const logout = (req, res) => {
  res.cookie("token", "", {
    httpOnly: process.env.NODE_ENV === "production",
    secure: process.env.NODE_ENV === "production",
    expires: new Date(0),
  });
  res.sendStatus(204);
};

export const profile = async (req, res) => {
  const token = req.cookies["token"];

  if (!token) return res.status(401).json({ error: "User not authenticated" });

  try {
    const payload = jwt.verify(token, process.env.TOKEN_SECRET);

    const user = await prisma.user.findUnique({
      where: {
        id: payload.id,
      },
      select: {
        id: true,
        username: true,
        email: true,
        role: {
          select: {
            role: true,
          },
        },
      },
    });

    res.json(user);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
};

export const verifyToken = async (req, res) => {
  const token = req.cookies["token"];

  if (!token) return res.status(401).json({ error: "User not authenticated" });

  try {
    const payload = jwt.verify(token, process.env.TOKEN_SECRET);

    res.json(payload);
  } catch (error) {
    res.status(401).json({ error: "User not authenticated" });
  }
};
