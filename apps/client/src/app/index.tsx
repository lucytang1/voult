import { Link } from "expo-router";
import { Pressable, Text, View } from "react-native";

export default function Home() {
  
  return (
    <View className="flex-1 items-center justify-center bg-black px-6">
      <Text className="text-white text-2xl mb-6">Password Manager</Text>
      <Link href={"/auth/login" as any} asChild>
        <Pressable className="w-full rounded-md bg-blue-600 py-2 items-center mb-3">
          <Text className="text-white">Log in</Text>
        </Pressable>
      </Link>
      <Link href={"/auth/signup" as any} asChild>
        <Pressable className="w-full rounded-md bg-white py-2 items-center">
          <Text className="text-black">Sign up</Text>
        </Pressable>
      </Link>
    </View>
  );
}
