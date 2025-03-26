from dotenv import load_dotenv
import os
import unittest
import requests


load_dotenv() 

base_url = os.getenv("BACKEND_URL")
username = os.getenv("TESTING_USERNAME")
password = os.getenv("TESTING_PASSWORD")
email = os.getenv("TESTING_EMAIL")


class TestAPI(unittest.TestCase):
    def test_health_check(self):
        response = requests.get(f"{base_url}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "Hello from Luma API!")
    
    def test_admin_check(self):
        response = requests.get(f"{base_url}/admin/check")
        self.assertEqual(response.status_code, 200)
        self.assertIn(response.text, ["true", "false"])
    
    def test_login(self):
        data = {"username": username, "password": password}
        response = requests.post(f"{base_url}/login", json=data)
        self.assertEqual(response.status_code, 200)
        response = response.json()
        
        self.assertIn("user", response)
        self.assertIn("username", response["user"])
    
    def test_refresh_token(self):
        # Login to get cookies
        data = {"username": username, "password": password}
        login_response = requests.post(f"{base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        cookies = login_response.cookies
        
        headers = {
            'Cookie': f'refresh_token={cookies.get("refresh_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https'
        }
        
        response = requests.post(
            f"{base_url}/refresh",
            headers=headers,
            verify=True
        )
        
        self.assertEqual(response.status_code, 200)
        
    
    def test_get_current_user(self):
        data = {"username": username, "password": password}
        login_response = requests.post(f"{base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        cookies = login_response.cookies
        
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }
        
        # Make request to get current user info
        response = requests.get(
            f"{base_url}/me",
            headers=headers,
            verify=True 
        )
        
        # Verify response status
        self.assertEqual(response.status_code, 200)
        
        # Parse and validate user data
        user_data = response.json()
        
        # Print user data for debugging
        print("\nCurrent User Information:")
        print(f"Username: {user_data.get('username')}")
        print(f"Email: {user_data.get('email')}")
        print(f"Role: {user_data.get('role')}")
        
        # Validate required fields exist
        required_fields = ["id", "username", "email", "role"]
        for field in required_fields:
            self.assertIn(field, user_data, f"Missing required field: {field}")
        
        # Validate field values
        self.assertEqual(user_data["username"], username, "Username mismatch")
        self.assertEqual(user_data["email"], email, "Email mismatch")
        self.assertIn(user_data["role"], ["admin", "user"], "Invalid role")
        
    def test_logout(self):
        # Login to get cookies
        data = {"username": username, "password": password}
        login_response = requests.post(f"{base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        # Extract cookies from login response
        cookies = login_response.cookies
        
        # Create headers with secure cookie attributes
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }

        response = requests.post(
            f"{base_url}/logout",
            headers=headers,
            verify=True
        )

        self.assertEqual(response.status_code, 200)

    # Users
    # user management endpoints
    # def test_admin(self):
    #     data = {"username": username, "password": password}
    #     login_response = requests.post(f"{base_url}/login", json=data)
    #     self.assertEqual(login_response.status_code, 200)
    #     cookies = login_response.cookies

    #     header = {
    #         'Cookie': f'access_token={cookies.get("refresh_token")}; Secure; HttpOnly; SameSite=Strict',
    #         'X-Forwarded-Proto': 'https'
    #     }

    #     response = requests.post(
    #         f"{base_url}/admin",
    #         headers=header,
    #         verify=True
    #     )

    #     data = {"username": self.api_test.username, "password": self.api_test.password}
    #     login_response = self.api_test.requests.post(f"{self.api_test.base_url}/login", json=data)
    #     self.assertEqual(login_response.status_code, 200)
        
        
        

    # Get user by serch 
    def test_get_user_search(self):
        # Login to get cookies
        data = {"username": username, "password": password}
        login_response = requests.post(f"{base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        # Extract cookies from login response
        cookies = login_response.cookies
        
        # Create headers with secure cookie attributes
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }

        response = requests.get(
            f"{base_url}/users",
            headers=headers,
            verify=True,
            params={"query": "neok"}
        )

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        required_fields = ["id", "username", "email", "role"]

        for user in response_data.get("users", []):  # Ensure 'users' exists and is iterable
            for field in required_fields:
                self.assertIn(field, user, f"Missing required field: {field}")


    def test_get_user_id(self):
        # Login to get cookies
        data = {"username": username, "password": password}
        login_response = requests.post(f"{base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        # Extract cookies from login response
        cookies = login_response.cookies
        
        # Create headers with secure cookie attributes
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }

        response = requests.get(
            f"{base_url}/users/1",
            headers=headers,
            verify=True
        )

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        required_fields = ["id", "username", "email", "role"]
        for field in required_fields:
            self.assertIn(field, response_data, f"Missing required field: {field}")

    # need to implement
    # def test_delete_user(self):
    #     # Login to get cookies
    #     data = {"username": username, "password": password}
    #     login_response = requests.post(f"{base_url}/login", json=data)
    #     self.assertEqual(login_response.status_code, 200)
        
    #     # Extract cookies from login response
    #     cookies = login_response.cookies
        
    #     # Create headers with secure cookie attributes
    #     headers = {
    #         'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
    #         'X-Forwarded-Proto': 'https' 
    #     }

    #     response = requests.delete(
    #         f"{base_url}/users/1",
    #         headers=headers,
    #         verify=True
    #     )  

    #     self.assertEqual(response.status_code, 204)

    def test_invitation(self):
        """Test the invitation endpoint with various scenarios"""
        # Login to get cookies
        data = {"username": username, "password": password}
        login_response = requests.post(f"{base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)

        cookies = login_response.cookies
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }

        # Send invitation request with authentication
        invitation_data = {
            "email": "test@example.com",
            "role": "user",
            "invite-token": "invitation-token"
        }
        response = requests.post(
            f"{base_url}/invitations",
            json=invitation_data,
            headers=headers
        )

        # print("Invitation response:", response.status_code, response.text)
        # self.assertEqual(response.status_code, 201)
        self.assertEqual(response.status_code, 200)

        response_json = response.json()
        self.assertIn("id", response_json)
        self.assertEqual(response_json["email"], "test@example.com")
        self.assertEqual(response_json["role"], "user")
        self.assertIn("token", response_json)

    def test_register(self):
        # Test successful registration
        
        payload = {
            "username": "new_user",
            "password": "password123"
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "test-client"
        }

        
        # response = requests.post(f"{base_url}/register", json=payload, headers=headers)

        # print("Response:", response.status_code, response.text)
        # self.assertEqual(response.status_code, 200, "Expected status code 200 Created")

if __name__ == "__main__":
    unittest.main()