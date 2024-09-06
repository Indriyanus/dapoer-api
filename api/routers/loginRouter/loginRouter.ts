import { Router } from "express";
import {checkLogin} from "../../middleware/validation/checkLogin";
import {loginValidation} from "../../middleware/validation/loginValidation";
import {login} from "../../controllers/loginController/loginController";
const router = Router()

router.post("/", checkLogin, loginValidation, login)

export default router