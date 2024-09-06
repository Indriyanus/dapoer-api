import { Router } from "express";
import {createMessage} from "../../controllers/contactController/contactController";

const router = Router();

router.post("/", createMessage);

export default router;
