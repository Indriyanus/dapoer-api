import { Router } from "express";
import {getMessages} from "../../controllers/messageController/messageController";

const router = Router();

router.get("/", getMessages);

export default router;