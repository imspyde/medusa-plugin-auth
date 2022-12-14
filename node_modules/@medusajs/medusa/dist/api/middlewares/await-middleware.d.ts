import { Request, RequestHandler, Response } from "express";
declare type handler = (req: Request, res: Response) => Promise<void>;
declare const _default: (fn: handler) => RequestHandler;
export default _default;
/**
 * @schema multiple_errors
 * title: "Multiple Errors"
 * x-resourceId: multiple_errors
 * properties:
 *  errors:
 *    type: array
 *    description: Array of errors
 *    items:
 *      $ref: "#/components/schemas/error"
 *  message:
 *    type: string
 *    default: "Provided request body contains errors. Please check the data and retry the request"
 */
