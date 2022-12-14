/**
 * @oas [get] /shipping-options
 * operationId: GetShippingOptions
 * summary: Get Shipping Options
 * description: "Retrieves a list of Shipping Options."
 * parameters:
 *   - (query) is_return {boolean} Whether return Shipping Options should be included. By default all Shipping Options are returned.
 *   - (query) product_ids {string} A comma separated list of Product ids to filter Shipping Options by.
 *   - (query) region_id {string} the Region to retrieve Shipping Options from.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.shippingOptions.list()
 *       .then(({ shipping_options }) => {
 *         console.log(shipping_options.length);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request GET 'https://medusa-url.com/store/shipping-options'
 * tags:
 *   - Shipping Option
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             shipping_options:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/shipping_option"
 *   "400":
 *     $ref: "#/components/responses/400_error"
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
export declare class StoreGetShippingOptionsParams {
    product_ids?: string;
    region_id?: string;
    is_return?: string;
}
