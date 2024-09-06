import { Router } from "express";
import {profile} from "../../controllers/profileController/profileController";
const router = Router();

router.get("/", profile);

export default router;