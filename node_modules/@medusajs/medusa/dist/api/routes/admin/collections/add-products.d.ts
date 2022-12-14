import { Request, Response } from "express";
/**
 * @oas [post] /collections/{id}/products/batch
 * operationId: "PostProductsToCollection"
 * summary: "Update Products"
 * description: "Updates products associated with a Product Collection"
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Collection.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - product_ids
 *         properties:
 *           product_ids:
 *             description: "An array of Product IDs to add to the Product Collection."
 *             type: array
 *             items:
 *               description: "The ID of a Product to add to the Product Collection."
 *               type: string
 * x-codeSamples:
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/collections/{id}/products/batch' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "product_ids": [
 *               "prod_01G1G5V2MBA328390B5AXJ610F"
 *           ]
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Collection
 * responses:
 *  "200":
 *    description: OK
 *    content:
 *      application/json:
 *        schema:
 *          properties:
 *            collection:
 *              $ref: "#/components/schemas/product_collection"
 *  "400":
 *    $ref: "#/components/responses/400_error"
 *  "401":
 *    $ref: "#/components/responses/unauthorized"
 *  "404":
 *    $ref: "#/components/responses/not_found_error"
 *  "409":
 *    $ref: "#/components/responses/invalid_state_error"
 *  "422":
 *    $ref: "#/components/responses/invalid_request_error"
 *  "500":
 *    $ref: "#/components/responses/500_error"
 */
declare const _default: (req: Request, res: Response) => Promise<void>;
export default _default;
export declare class AdminPostProductsToCollectionReq {
    product_ids: string[];
}
