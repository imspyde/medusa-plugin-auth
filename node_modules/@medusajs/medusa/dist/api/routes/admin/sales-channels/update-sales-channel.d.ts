import { Request, Response } from "express";
/**
 * @oas [post] /sales-channels/{id}
 * operationId: "PostSalesChannelsSalesChannel"
 * summary: "Update a Sales Channel"
 * description: "Updates a Sales Channel."
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Sales Channel.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         properties:
 *           name:
 *             type: string
 *             description: Name of the sales channel.
 *           description:
 *             type: string
 *             description:  Sales Channel description.
 *           is_disabled:
 *             type: boolean
 *             description:  Indication of if the sales channel is active.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.salesChannels.update(sales_channel_id, {
 *         name: 'App'
 *       })
 *       .then(({ sales_channel }) => {
 *         console.log(sales_channel.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/sales-channels/{id}' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "name": "App"
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Sales Channel
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             sales_channel:
 *               $ref: "#/components/schemas/sales_channel"
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
export declare class AdminPostSalesChannelsSalesChannelReq {
    name?: string;
    description?: string;
    is_disabled?: boolean;
}
