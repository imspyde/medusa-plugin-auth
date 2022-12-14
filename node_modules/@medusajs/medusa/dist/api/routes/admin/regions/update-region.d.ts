/**
 * @oas [post] /regions/{id}
 * operationId: "PostRegionsRegion"
 * summary: "Update a Region"
 * description: "Updates a Region"
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Region.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
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
 *           automatic_taxes:
 *             description: "If true Medusa will automatically calculate taxes for carts in this region. If false you have to manually call POST /carts/:id/taxes."
 *             type: boolean
 *           gift_cards_taxable:
 *             description: "Whether gift cards in this region should be applied sales tax when purchasing a gift card"
 *             type: boolean
 *           tax_provider_id:
 *             description: "The ID of the tax provider to use; if null the system tax provider is used"
 *             type: string
 *           tax_code:
 *             description: "An optional tax code the Region."
 *             type: string
 *           tax_rate:
 *             description: "The tax rate to use on Orders in the Region."
 *             type: number
 *           includes_tax:
 *             description: "[EXPERIMENTAL] Tax included in prices of region"
 *             type: boolean
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
 *             type: array
 *             items:
 *               type: string
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.regions.update(region_id, {
 *         name: 'Europe'
 *       })
 *       .then(({ region }) => {
 *         console.log(region.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/regions/{id}' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "name": "Europe"
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
export declare class AdminPostRegionsRegionReq {
    name?: string;
    currency_code?: string;
    tax_code?: string;
    tax_rate?: number;
    gift_cards_taxable?: boolean;
    automatic_taxes?: boolean;
    tax_provider_id?: string | null;
    payment_providers?: string[];
    fulfillment_providers?: string[];
    countries?: string[];
    includes_tax?: boolean;
    metadata?: Record<string, unknown>;
}
