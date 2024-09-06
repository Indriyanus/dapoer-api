import { Request, Response, NextFunction } from "express";
import { prisma } from "../../connection/index";

export const getProducts = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const products = await prisma.product.findMany();
    res.status(200).json({
      error: false,
      message: "Products fetched successfully",
      data: products,
    });
  } catch (error) {
    next(error);
  }
};
