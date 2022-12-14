import { AdminPriceListPricesCreateReq, PriceListStatus, PriceListType } from "../../../../types/price-list";
import { Request } from "express";
/**
 * @oas [post] /price-lists
 * operationId: "PostPriceListsPriceList"
 * summary: "Create a Price List"
 * description: "Creates a Price List"
 * x-authenticated: true
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - name
 *           - description
 *           - type
 *           - prices
 *         properties:
 *           name:
 *             description: "The name of the Price List"
 *             type: string
 *           description:
 *             description: "A description of the Price List."
 *             type: string
 *           starts_at:
 *             description: "The date with timezone that the Price List starts being valid."
 *             type: string
 *             format: date
 *           ends_at:
 *             description: "The date with timezone that the Price List ends being valid."
 *             type: string
 *             format: date
 *           type:
 *             description: The type of the Price List.
 *             type: string
 *             enum:
 *              - sale
 *              - override
 *           status:
 *             description: The status of the Price List.
 *             type: string
 *             enum:
 *               - active
 *               - draft
 *           prices:
 *              description: The prices of the Price List.
 *              type: array
 *              items:
 *                required:
 *                  - amount
 *                  - variant_id
 *                properties:
 *                  region_id:
 *                    description: The ID of the Region for which the price is used. Only required if currecny_code is not provided.
 *                    type: string
 *                  currency_code:
 *                    description: The 3 character ISO currency code for which the price will be used. Only required if region_id is not provided.
 *                    type: string
 *                    externalDocs:
 *                      url: https://en.wikipedia.org/wiki/ISO_4217#Active_codes
 *                      description: See a list of codes.
 *                  amount:
 *                    description: The amount to charge for the Product Variant.
 *                    type: integer
 *                  variant_id:
 *                    description: The ID of the Variant for which the price is used.
 *                    type: string
 *                  min_quantity:
 *                    description: The minimum quantity for which the price will be used.
 *                    type: integer
 *                  max_quantity:
 *                    description: The maximum quantity for which the price will be used.
 *                    type: integer
 *           customer_groups:
 *             type: array
 *             description: A list of customer groups that the Price List applies to.
 *             items:
 *               required:
 *                 - id
 *               properties:
 *                 id:
 *                   description: The ID of a customer group
 *                   type: string
 *           includes_tax:
 *              description: "[EXPERIMENTAL] Tax included in prices of price list"
 *              type: boolean
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       import { PriceListType } from "@medusajs/medusa"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.priceLists.create({
 *         name: 'New Price List',
 *         description: 'A new price list',
 *         type: PriceListType.SALE,
 *         prices: [
 *           {
 *             amount: 1000,
 *             variant_id,
 *             currency_code: 'eur'
 *           }
 *         ]
 *       })
 *       .then(({ price_list }) => {
 *         console.log(price_list.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/price-lists' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "name": "New Price List",
 *           "description": "A new price list",
 *           "type": "sale",
 *           "prices": [
 *             {
 *               "amount": 1000,
 *               "variant_id": "afafa",
 *               "currency_code": "eur"
 *             }
 *           ]
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Price List
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             price_list:
 *               $ref: "#/components/schemas/price_list"
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
declare class CustomerGroup {
    id: string;
}
export declare class AdminPostPriceListsPriceListReq {
    name: string;
    description: string;
    starts_at?: Date;
    ends_at?: Date;
    status?: PriceListStatus;
    type: PriceListType;
    prices: AdminPriceListPricesCreateReq[];
    customer_groups?: CustomerGroup[];
    includes_tax?: boolean;
}
