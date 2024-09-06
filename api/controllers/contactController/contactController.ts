import { Request, Response, NextFunction } from "express";
import { prisma } from "../../connection/index";

export const createMessage = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, email, phone, product, message } = req.body;
    console.log('Received data:', { name, email, phone, product, message });

    const productData = await prisma.product.findFirst({
      where: {
        name: product,
      },
    });

    if (!productData) {
      console.log('Product not found');
      return res.status(400).json({ error: true, message: 'Product not found' });
    }

    const newMessage = await prisma.pesan.create({
      data: {
        name,
        email,
        phone,
        productName: product,
        message,
        productId: productData.id,
      },
    });

    res.status(201).json({
      error: false,
      message: 'Message sent successfully',
      data: newMessage,
    });
  } catch (error) {
    console.error('Error creating message:', error);
    res.status(500).json({ error: true, message: 'Internal Server Error' });
  }
};
