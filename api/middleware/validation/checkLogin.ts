import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export const checkLogin = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return next();
  }

  jwt.verify(token, "dpng2024", (err, decoded) => {
    if (err) {
      return next();
    }

    return res.status(403).json({ message: "You are already logged in" });
  });
};