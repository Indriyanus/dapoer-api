import { Request, Response, NextFunction } from "express";

export const position = async(req: Request, res: Response, next: NextFunction) => {
    try {
        const positions = [
            "STAFF",
            "LEADER",
            "ASMAN",
            "MANAGER",
            "DIREKTUR_OPERASIONAL",
            "KOMISARIS",
            "CEO"
        ];
        res.status(200).json({ positions });
    } catch (error) {
        next(error)
    }
}