/**
 * @oas [post] /customers
 * operationId: PostCustomers
 * summary: Create a Customer
 * description: "Creates a Customer account."
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - first_name
 *           - last_name
 *           - email
 *           - password
 *         properties:
 *           first_name:
 *             description: "The Customer's first name."
 *             type: string
 *           last_name:
 *             description: "The Customer's last name."
 *             type: string
 *           email:
 *             description: "The email of the customer."
 *             type: string
 *             format: email
 *           password:
 *             description: "The Customer's password."
 *             type: string
 *             format: password
 *           phone:
 *             description: "The Customer's phone number."
 *             type: string
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.customers.create({
 *         first_name: 'Alec',
 *         last_name: 'Reynolds',
 *         email: 'user@example.com',
 *         password: 'supersecret'
 *       })
 *       .then(({ customer }) => {
 *         console.log(customer.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/store/customers' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "first_name": "Alec",
 *           "last_name": "Reynolds",
 *           "email": "user@example.com",
 *           "password": "supersecret"
 *       }'
 * tags:
 *   - Customer
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             customer:
 *               $ref: "#/components/schemas/customer"
 *   422:
 *     description: A customer with the same email exists
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             code:
 *               type: string
 *               description: The error code
 *             type:
 *               type: string
 *               description: The type of error
 *             message:
 *               type: string
 *               description: Human-readable message with details about the error
 *         example:
 *           code: "invalid_request_error"
 *           type: "duplicate_error"
 *           message: "A customer with the given email already has an account. Log in instead"
 *   "400":
 *     $ref: "#/components/responses/400_error"
 *   "404":
 *     $ref: "#/components/responses/not_found_error"
 *   "409":
 *     $ref: "#/components/responses/invalid_state_error"
 *   "500":
 *     $ref: "#/components/responses/500_error"
 */
declare const _default: (req: any, res: any) => Promise<void>;
export default _default;
export declare class StorePostCustomersReq {
    first_name: string;
    last_name: string;
    email: string;
    password: string;
    phone?: string;
}
