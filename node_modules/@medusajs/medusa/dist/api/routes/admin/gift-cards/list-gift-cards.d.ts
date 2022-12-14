/**
 * @oas [get] /gift-cards
 * operationId: "GetGiftCards"
 * summary: "List Gift Cards"
 * description: "Retrieves a list of Gift Cards."
 * x-authenticated: true
 * parameters:
 *   - (query) offset=0 {number} The number of items to skip before the results.
 *   - (query) limit=50 {number} Limit the number of items returned.
 *   - (query) q {string} a search term to search by code or display ID
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.giftCards.list()
 *       .then(({ gift_cards, limit, offset, count }) => {
 *         console.log(gift_cards.length);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request GET 'https://medusa-url.com/admin/gift-cards' \
 *       --header 'Authorization: Bearer {api_token}'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Gift Card
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             gift_cards:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/gift_card"
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
declare const _default: (req: any, res: any) => Promise<void>;
export default _default;
export declare class AdminGetGiftCardsParams {
    limit: number;
    offset: number;
    q?: string;
}
