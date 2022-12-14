/**
 * @oas [post] /regions
 * operationId: "PostRegions"
 * summary: "Create a Region"
 * description: "Creates a Region"
 * x-authenticated: true
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - name
 *           - currency_code
 *           - tax_rate
 *           - payment_providers
 *           - fulfillment_providers
 *           - countries
 *         properties:
 *           name:
 *             description: "The name of the Region"
 *             type: string
 *           currency_code:
 *             description: "The 3 character ISO currency code to use for the Region."
 *             type: string
 *             externalDocs:
 *               url: https://en.wikipedia.org/wiki/ISO_4217#Active_codes
 *               description: See a list of codes.
 *           tax_code:
 *             description: "An optional tax code the Region."
 *             type: string
 *           tax_rate:
 *             description: "The tax rate to use on Orders in the Region."
 *             type: number
 *           payment_providers:
 *             description: "A list of Payment Provider IDs that should be enabled for the Region"
 *             type: array
 *             items:
 *               type: string
 *           fulfillment_providers:
 *             description: "A list of Fulfillment Provider IDs that should be enabled for the Region"
 *             type: array
 *             items:
 *               type: string
 *           countries:
 *             description: "A list of countries' 2 ISO Characters that should be included in the Region."
 *             example: ["US"]
 *             type: array
 *             items:
 *               type: string
 *           includes_tax:
 *             description: "[EXPERIMENTAL] Tax included in prices of region"
 *             type: boolean
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.regions.create({
 *         name: 'Europe',
 *         currency_code: 'eur',
 *         tax_rate: 0,
 *         payment_providers: [
 *           'manual'
 *         ],
 *         fulfillment_providers: [
 *           'manual'
 *         ],
 *         countries: [
 *           'DK'
 *         ]
 *       })
 *       .then(({ region }) => {
 *         console.log(region.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/regions' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "name": "Europe",
 *           "currency_code": "eur",
 *           "tax_rate": 0,
 *           "payment_providers": [
 *             "manual"
 *           ],
 *           "fulfillment_providers": [
 *             "manual"
 *           ],
 *           "countries": [
 *             "DK"
 *           ]
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Region
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             region:
 *               $ref: "#/components/schemas/region"
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
declare const _default: (req: any, res: any) => Promise<void>;
export default _default;
export declare class AdminPostRegionsReq {
    name: string;
    currency_code: string;
    tax_code?: string;
    tax_rate: number;
    payment_providers: string[];
    fulfillment_providers: string[];
    countries: string[];
    includes_tax?: boolean;
    metadata?: Record<string, unknown>;
}
