import { Router } from "express";
import {getProducts} from "../../controllers/productController/productController";

const router = Router();

router.get("/list", getProducts);

export default router;
