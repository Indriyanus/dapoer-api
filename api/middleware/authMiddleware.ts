import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    req.user = undefined;  // Ubah dari null ke undefined
    return next();
  }

  jwt.verify(token, "dpng2024", (err, decoded) => {
    if (err) {
      req.user = undefined;  // Ubah dari null ke undefined
    } else {
      req.user = decoded;
    }
    next();
  });
};