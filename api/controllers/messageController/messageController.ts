import { Request, Response, NextFunction } from "express";
import { prisma } from "../../connection/index";

export const getMessages = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const messages = await prisma.pesan.findMany({
      include: { product: true },
    });
    res.status(200).json({
      error: false,
      message: "Messages fetched successfully",
      data: messages,
    });
  } catch (error) {
    next(error);
  }
};