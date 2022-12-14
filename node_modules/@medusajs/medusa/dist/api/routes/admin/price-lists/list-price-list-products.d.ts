import { DateComparisonOperator } from "../../../../types/common";
import { ProductStatus } from "../../../../models";
import { Request } from "express";
/**
 * @oas [get] /price-lists/{id}/products
 * operationId: "GetPriceListsPriceListProducts"
 * summary: "List Products"
 * description: "Retrieves a list of Product that are part of a Price List"
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} ID of the price list.
 *   - (query) q {string} Query used for searching product title and description, variant title and sku, and collection title.
 *   - (query) id {string} ID of the product to search for.
 *   - in: query
 *     name: status
 *     description: Product status to search for
 *     style: form
 *     explode: false
 *     schema:
 *       type: array
 *       items:
 *         type: string
 *         enum: [draft, proposed, published, rejected]
 *   - in: query
 *     name: collection_id
 *     description: Collection IDs to search for
 *     style: form
 *     explode: false
 *     schema:
 *       type: array
 *       items:
 *         type: string
 *   - in: query
 *     name: tags
 *     description: Tag IDs to search for
 *     style: form
 *     explode: false
 *     schema:
 *       type: array
 *       items:
 *         type: string
 *   - (query) title {string} product title to search for.
 *   - (query) description {string} product description to search for.
 *   - (query) handle {string} product handle to search for.
 *   - (query) is_giftcard {string} Search for giftcards using is_giftcard=true.
 *   - (query) type {string} to search for.
 *   - (query) order {string} field to sort results by.
 *   - in: query
 *     name: created_at
 *     description: Date comparison for when resulting products were created.
 *     schema:
 *       type: object
 *       properties:
 *         lt:
 *            type: string
 *            description: filter by dates less than this date
 *            format: date
 *         gt:
 *            type: string
 *            description: filter by dates greater than this date
 *            format: date
 *         lte:
 *            type: string
 *            description: filter by dates less than or equal to this date
 *            format: date
 *         gte:
 *            type: string
 *            description: filter by dates greater than or equal to this date
 *            format: date
 *   - in: query
 *     name: updated_at
 *     description: Date comparison for when resulting products were updated.
 *     schema:
 *       type: object
 *       properties:
 *         lt:
 *            type: string
 *            description: filter by dates less than this date
 *            format: date
 *         gt:
 *            type: string
 *            description: filter by dates greater than this date
 *            format: date
 *         lte:
 *            type: string
 *            description: filter by dates less than or equal to this date
 *            format: date
 *         gte:
 *            type: string
 *            description: filter by dates greater than or equal to this date
 *            format: date
 *   - in: query
 *     name: deleted_at
 *     description: Date comparison for when resulting products were deleted.
 *     schema:
 *       type: object
 *       properties:
 *         lt:
 *            type: string
 *            description: filter by dates less than this date
 *            format: date
 *         gt:
 *            type: string
 *            description: filter by dates greater than this date
 *            format: date
 *         lte:
 *            type: string
 *            description: filter by dates less than or equal to this date
 *            format: date
 *         gte:
 *            type: string
 *            description: filter by dates greater than or equal to this date
 *            format: date
 *   - (query) offset=0 {integer} How many products to skip in the result.
 *   - (query) limit=50 {integer} Limit the number of products returned.
 *   - (query) expand {string} (Comma separated) Which fields should be expanded in each product of the result.
 *   - (query) fields {string} (Comma separated) Which fields should be included in each product of the result.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.priceLists.listProducts(price_list_id)
 *       .then(({ products, limit, offset, count }) => {
 *         console.log(products.length);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request GET 'https://medusa-url.com/admin/price-lists/{id}/products' \
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
 *             products:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/product"
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
declare const _default: (req: Request, res: any) => Promise<void>;
export default _default;
declare const AdminGetPriceListsPriceListProductsParams_base: import("../../../../types/global").ClassConstructor<import("../../../../types/common").FindParams & import("../../../../types/common").FindPaginationParams>;
export declare class AdminGetPriceListsPriceListProductsParams extends AdminGetPriceListsPriceListProductsParams_base {
    id?: string;
    q?: string;
    status?: ProductStatus[];
    collection_id?: string[];
    tags?: string[];
    title?: string;
    description?: string;
    handle?: string;
    is_giftcard?: string;
    type?: string;
    order?: string;
    created_at?: DateComparisonOperator;
    updated_at?: DateComparisonOperator;
    deleted_at?: DateComparisonOperator;
}
