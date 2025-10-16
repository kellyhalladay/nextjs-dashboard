import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcrypt';

async function getUser(email) {
  try {
    const sql = neon(`${process.env.DATABASE_URL}`);
    const users = await sql`SELECT * FROM users WHERE email=${email}`;

    console.log('🧠 Query result:', users);

    if (!users) {
      return null;
    }
    return users;
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        console.log('🟡 Incoming credentials:', credentials);

        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsedCredentials.success) {
          console.log('⚠️ Invalid credentials format');
          return null;
        }

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          console.log('🟢 User from DB:', user);

          if (!user) {
            console.log('❌ No user found');
            return null;
          }
          const passwordsMatch = await bcrypt.compare(password, user[0].password);
          console.log('🔵 Password match?', passwordsMatch);

          if (passwordsMatch) {
            console.log('✅ Login success!');
            return {
              id: user.id,
              name: user.name,
              email: user.email,
            };
          }
        }
        console.log('Invalid Credentials');
        return null;
      },
    }),
  ],
});
