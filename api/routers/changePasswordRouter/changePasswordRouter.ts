import { Router } from "express";
import {changePassword} from "../../controllers/changePasswordController/changePasswordController";
const router = Router();

router.post("/", changePassword);

export default router;
