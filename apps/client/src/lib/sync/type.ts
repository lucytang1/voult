import * as z from "zod";


export const UpdateVaultItemSchema = z.object({
  id: z.uuid(),
  fields: z.object({
    site: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
  }),
});
type UpdateVaultItem = z.infer<typeof UpdateVaultItemSchema>;

export const DeleteVaultItemSchema = z.object({
  id: z.uuid(),
});
type DeleteVaultItem = z.infer<typeof DeleteVaultItemSchema>;

export const CreateVaultItemSchema = z.object({
  id: z.uuid(),
  site: z.string(),
  username: z.string(),
  password: z.string(),
});
type CreateVaultItem = z.infer<typeof CreateVaultItemSchema>;

export { UpdateVaultItem, DeleteVaultItem, CreateVaultItem };
