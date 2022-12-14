import { NextFunction, Request, Response } from "express";
import { ProductBatchSalesChannel } from "../../../types/sales-channels";
export declare function validateProductsExist(getProducts: (req: any) => ProductBatchSalesChannel[] | undefined): (req: Request, res: Response, next: NextFunction) => Promise<void>;
