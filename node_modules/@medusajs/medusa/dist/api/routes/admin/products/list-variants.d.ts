import { Request, Response } from "express";
/**
 * @oas [get] /products/{id}/variants
 * operationId: "GetProductsProductVariants"
 * summary: "List a Product's Variants"
 * description: "Retrieves a list of the Product Variants associated with a Product."
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} ID of the product to search for the variants.
 *   - (query) fields {string} Comma separated string of the column to select.
 *   - (query) expand {string} Comma separated string of the relations to include.
 *   - (query) offset=0 {integer} How many items to skip before the results.
 *   - (query) limit=100 {integer} Limit the number of items returned.
 * x-codeSamples:
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request GET 'https://medusa-url.com/admin/products/{id}/variants' \
 *       --header 'Authorization: Bearer {api_token}'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Product
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             variants:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/product_variant"
 *             count:
 *               type: integer
 *               description: The total number of items available
 *             offset:
 *               type: integer
 *               description: The number of items skipped before these items
 *             limit:
 *               type: integer
 *               description: The number of items per page
 *   "400":
 *     $ref: "#/components/responses/400_error"
 *   "401":
 *     $ref: "#/components/responses/unauthorized"
 *   "404":
 *     $ref: "#/components/responses/not_found_error"
 *   "409":
 *     $ref: "#/components/responses/invalid_state_error"
 *   "422":
 *     $ref: "#/components/responses/invalid_request_error"
 *   "500":
 *     $ref: "#/components/responses/500_error"
 */
declare const _default: (req: Request, res: Response) => Promise<void>;
export default _default;
export declare class AdminGetProductsVariantsParams {
    fields?: string;
    expand?: string;
    offset?: number;
    limit?: number;
}
