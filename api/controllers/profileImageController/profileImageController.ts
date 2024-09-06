import { Request, Response, NextFunction } from "express";
import { prisma } from "../../connection/index";
import multer from "multer";
import path from "path";
import fs from "fs";

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = 'public/uploads/profile-images/';
    if (!fs.existsSync(dir)){
        fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); // Append the file extension
  }
});

const upload = multer({ storage: storage });

export const uploadProfileImage = [
  upload.single('image'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { penggunaId } = req.body;
      if (!penggunaId) {
        return res.status(400).json({ error: true, message: 'penggunaId is missing' });
      }

      if (!req.file) {
        return res.status(400).json({ error: true, message: 'No file uploaded' });
      }

      const pengguna = await prisma.pengguna.findUnique({
        where: { id: Number(penggunaId) },
        include: { profileImage: true }
      });

      if (!pengguna) {
        return res.status(404).json({ error: true, message: 'User not found' });
      }

      // Hapus gambar profil lama jika ada
      if (pengguna.profileImage) {
        const oldImagePath = path.join(__dirname, '../../../public/uploads/profile-images/', pengguna.profileImage.name);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath); // Hapus file lama
        }

        // Hapus data gambar lama dari database
        await prisma.profileImage.delete({
          where: { id: pengguna.profileImage.id }
        });
      }

      // Simpan gambar baru
      const newProfileImage = await prisma.profileImage.create({
        data: {
          name: req.file.filename,
          url: req.file.path.replace(/\\/g, '/'), // Mengganti backslashes dengan forward slashes
          penggunaId: pengguna.id,
        },
      });

      res.status(201).json({
        error: false,
        message: 'Profile image updated successfully',
        data: newProfileImage,
      });
    } catch (error) {
      next(error);
    }
  }
];
