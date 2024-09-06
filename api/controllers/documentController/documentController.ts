import { Request, Response, NextFunction } from "express";
import { prisma } from "../../connection/index";

export const createDocument = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, type, size, url, category, productCode } = req.body;
    console.log('Received data:', { name, type, size, url, category, productCode });

    if (category === 'Product') {
      // Temukan produk berdasarkan kode produk
      const productData = await prisma.product.findUnique({
        where: {
          code: productCode,
        },
      });

      if (!productData) {
        console.log('Product not found');
        return res.status(400).json({ error: true, message: 'Product not found' });
      }

      // Buat dokumen baru untuk produk
      const newDocument = await prisma.document.create({
        data: {
          name,
          type,
          size,
          url,
          category,
          productId: productData.id,
        },
      });

      res.status(201).json({
        error: false,
        message: 'Document created successfully for product',
        data: newDocument,
      });

    } else if (category === 'Notadinas') {
      // Temukan notadinas berdasarkan kode notadinas
      const notadinasData = await prisma.notadinas.findUnique({
        where: {
          code: productCode,
        },
      });

      if (!notadinasData) {
        console.log('Notadinas not found');
        return res.status(400).json({ error: true, message: 'Notadinas not found' });
      }

      // Buat dokumen baru untuk notadinas
      const newDocument = await prisma.document.create({
        data: {
          name,
          type,
          size,
          url,
          category,
          notadinasId: notadinasData.id,
        },
      });

      res.status(201).json({
        error: false,
        message: 'Document created successfully for notadinas',
        data: newDocument,
      });

    } else {
      return res.status(400).json({ error: true, message: 'Invalid category' });
    }
  } catch (error) {
    console.error('Error creating document:', error);
    res.status(500).json({ error: true, message: 'Internal Server Error' });
  }
};

export const getDocuments = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const documents = await prisma.document.findMany({
      include: {
        product: true,
        notadinas: true,
      }
    });

    res.status(200).json({
      error: false,
      data: documents,
    });
  } catch (error) {
    console.error('Error fetching documents:', error);
    res.status(500).json({ error: true, message: 'Internal Server Error' });
  }
};
