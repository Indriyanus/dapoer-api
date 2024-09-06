import fs from 'fs';
import path from 'path';
import { NextFunction, Request, Response } from 'express';

export const checkUploadsDir = (req: Request, res: Response, next: NextFunction) => {
  const dir = path.join(__dirname, '../../public/uploads/profile-images');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  next();
};
