/**
 * @oas [post] /regions/{id}/payment-providers
 * operationId: "PostRegionsRegionPaymentProviders"
 * summary: "Add Payment Provider"
 * description: "Adds a Payment Provider to a Region"
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Region.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - provider_id
 *         properties:
 *           provider_id:
 *             description: "The ID of the Payment Provider to add."
 *             type: string
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.regions.addPaymentProvider(region_id, {
 *         provider_id: 'manual'
 *       })
 *       .then(({ region }) => {
 *         console.log(region.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/regions/{id}/payment-providers' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "provider_id": "manual"
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
export declare class AdminPostRegionsRegionPaymentProvidersReq {
    provider_id: string;
}
