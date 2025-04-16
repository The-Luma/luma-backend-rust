from dotenv import load_dotenv
import os
import unittest
import requests

# Load variables from .env file
load_dotenv()


class TestAPI(unittest.TestCase):
    def setUp(self):
        # Testing user info
        self.base_url = os.getenv("BACKEND_URL")
        self.username = os.getenv("TESTING_USERNAME")
        self.password = os.getenv("TESTING_PASSWORD")
        self.email = os.getenv("TESTING_EMAIL")

        self.admin_data = {
            "username": os.getenv("TESTING_USERNAME"),
            "email": os.getenv("TESTING_EMAIL"),
            "password": os.getenv("TESTING_PASSWORD")
        }

        self.dummy_email = os.getenv('TESTING_DUMMY_EMAIL')
        self.dummy_username = os.getenv('TESTING_DUMMY_USERNAME')
        self.dummy_password = os.getenv('TESTING_DUMMY_PASSWORD')

    def test_health_check(self):
        response = requests.get(f"{self.base_url}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "Hello from Luma API!")
    
    def test_admin_check(self):
        response = requests.get(f"{self.base_url}/admin/check")
        self.assertEqual(response.status_code, 200)
        self.assertIn(response.text, ["true", "false"])
    
    def test_login(self):
        data = {"username": self.username, "password": self.password}
        response = requests.post(f"{self.base_url}/login", json=data)
        self.assertEqual(response.status_code, 200)
        response = response.json()
        
        self.assertIn("user", response)
        self.assertIn("username", response["user"])
    
    def test_refresh_token(self):
        # Login to get cookies
        data = {"username": self.username, "password": self.password}
        login_response = requests.post(f"{self.base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        cookies = login_response.cookies
        
        headers = {
            'Cookie': f'refresh_token={cookies.get("refresh_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https'
        }
        
        response = requests.post(
            f"{self.base_url}/refresh",
            headers=headers,
            verify=True
        )
        
        self.assertEqual(response.status_code, 200)
        
    
    def test_get_current_user(self):
        data = {"username": self.username, "password": self.password}
        login_response = requests.post(f"{self.base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        cookies = login_response.cookies
        
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }
        
        # Make request to get current user info
        response = requests.get(
            f"{self.base_url}/me",
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
        self.assertEqual(user_data["username"], self.username, "Username mismatch")
        self.assertEqual(user_data["email"], self.email, "Email mismatch")
        self.assertIn(user_data["role"], ["admin", "user"], "Invalid role")
        
    def test_logout(self):
        # Login to get cookies
        data = {"username": self.username, "password": self.password}
        login_response = requests.post(f"{self.base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        # Extract cookies from login response
        cookies = login_response.cookies
        
        # Create headers with secure cookie attributes
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }

        response = requests.post(
            f"{self.base_url}/logout",
            headers=headers,
            verify=True
        )

        self.assertEqual(response.status_code, 200)

    # Users
    # user management endpoints

    # Create firt admin
    def test_admin(self):

        admin_check_response = requests.get(f"{self.base_url}/admin/check")
        self.assertEqual(admin_check_response.status_code, 200)
        test_data = {
            "eami"
        }
        response = requests.post(
            f"{self.base_url}/admin",
            headers={
                'X-Forwarded-Proto': 'https',
                'Content-Type': 'application/json'
            },
            json=self.admin_data, 
            verify=True
        )


        # Print response for debugging
        # print("Status Code:", response.status_code)
        print("Response Body:", response.text)

        # Assert the status code
        if (admin_check_response.status_code != 200):
            self.assertEqual(response.status_code, 200)
        else:
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.text, "Admin already exists")

        # Assert response JSON contains expected keys
        json_data = response.json()
        self.assertEqual(json_data.get("username"), self.admin_data["username"])
        self.assertEqual(json_data.get("email"), self.admin_data["email"])
        self.assertEqual(json_data.get("role"), "admin")

        
        self.assertEqual(response.status_code, 200)
        
        

    # Get user by serch 
    def test_get_user_search(self):
        # Login to get cookies
        data = {"username": self.username, "password": self.password}
        login_response = requests.post(f"{self.base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        # Extract cookies from login response
        cookies = login_response.cookies
        
        # Create headers with secure cookie attributes
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }

        response = requests.get(
            f"{self.base_url}/users",
            headers=headers,
            verify=True,
            params={"query": "neok"}
        )

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        required_fields = ["id", "username", "email", "role"]

        for user in response_data.get("users", []):
            for field in required_fields:
                self.assertIn(field, user, f"Missing required field: {field}")


    def test_get_user_id(self):
        # Login to get cookies
        data = {"username": self.username, "password": self.password}
        login_response = requests.post(f"{self.base_url}/login", json=data)
        self.assertEqual(login_response.status_code, 200)
        
        # Extract cookies from login response
        cookies = login_response.cookies
        
        # Create headers with secure cookie attributes
        headers = {
            'Cookie': f'access_token={cookies.get("access_token")}; Secure; HttpOnly; SameSite=Strict',
            'X-Forwarded-Proto': 'https' 
        }

        response = requests.get(
            f"{self.base_url}/users/1",
            headers=headers,
            verify=True
        )

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        required_fields = ["id", "username", "email", "role"]
        for field in required_fields:
            self.assertIn(field, response_data, f"Missing required field: {field}")

    # def test_delete_user(self):
    #     """Test the user deletion endpoint with admin privileges"""
    #     # First, create an invitation to get a valid token
    #     # Login as admin
    #     admin_login_data = {
    #         "username": self.username,
    #         "password": self.password
    #     }
    #     admin_login_response = requests.post(
    #         f"{self.base_url}/login",
    #         json=admin_login_data
    #     )
    #     self.assertEqual(admin_login_response.status_code, 200)
        
    #     # Get admin auth token
    #     admin_cookies = admin_login_response.cookies
    #     admin_headers = {
    #         'Cookie': f'auth_token={admin_cookies.get("auth_token")}',
    #         'X-Forwarded-Proto': 'https'
    #     }
        
    #     # Create an invitation
    #     invitation_data = {
    #         "email": self.dummy_email,
    #         "role": "user"
    #     }
    #     invitation_response = requests.post(
    #         f"{self.base_url}/invitations",
    #         json=invitation_data,
    #         headers=admin_headers,
    #         verify=True
    #     )
    #     self.assertEqual(invitation_response.status_code, 200)
    #     invitation = invitation_response.json()
    #     invitation_token = invitation["token"]
        
    #     # Now create a test user with the real invitation token
    #     test_user_data = {
    #         "username": self.dummy_username,
    #         "password": self.dummy_password,
    #         "invitation_token": invitation_token
    #     }
        
    #     # Register the test user
    #     register_response = requests.post(
    #         f"{self.base_url}/register",
    #         json=test_user_data,
    #         headers={"Content-Type": "application/json"}
    #     )
    #     self.assertEqual(register_response.status_code, 200)
    #     test_user = register_response.json()
        
    #     # Admin deletes the test user
    #     admin_delete_response = requests.delete(
    #         f"{self.base_url}/users/{test_user['id']}",
    #         headers=admin_headers,
    #         verify=True
    #     )
    #     self.assertEqual(admin_delete_response.status_code, 204)
        
    #     # Verify user is deleted by trying to login
    #     verify_login = requests.post(
    #         f"{self.base_url}/login",
    #         json=test_user_data
    #     )
    #     self.assertEqual(verify_login.status_code, 401)

    def test_invitation(self):
        """Test the invitation endpoint with various scenarios"""
        # Login as admin
        admin_login_data = {
            "username": self.username,
            "password": self.password
        }
        admin_login_response = requests.post(
            f"{self.base_url}/login",
            json=admin_login_data
        )
        self.assertEqual(admin_login_response.status_code, 200)
        
        # Get admin auth token
        admin_cookies = admin_login_response.cookies
        admin_headers = {
            'Cookie': f'auth_token={admin_cookies.get("auth_token")}',
            'X-Forwarded-Proto': 'https'
        }

        admin_info_response = requests.get(
            f"{self.base_url}/me",
            headers=admin_headers,
            verify=True 
        )
        
        # Verify response status
        self.assertEqual(admin_info_response.status_code, 200)
        
        # Parse and validate user data
        user_data = admin_info_response.json()
        
        # Print user data for debugging
        print("\nCurrent User Information:")
        print(f"Username: {user_data.get('username')}")
        print(f"Email: {user_data.get('email')}")
        print(f"Role: {user_data.get('role')}")
        
        # Create invitation
        invitation_data = {
            "email": self.dummy_email,
            "role": "user"
        }

        invite_header = {
            'role': user_data.get('role'),
            'Cookie': f'auth_token={admin_cookies.get("auth_token")}',
            'X-Forwarded-Proto': 'https'
        }

        invitation_response = requests.post(
            f"{self.base_url}/invitations",
            data=invitation_data,
            headers=invite_header,
            verify=True
        )
        
        # Verify successful invitation creation
        self.assertEqual(invitation_response.status_code, 200)
        invitation = invitation_response.json()
        
        # Validate invitation data structure
        required_fields = ["id", "email", "role", "token", "created_at", "expires_at", "used"]
        for field in required_fields:
            self.assertIn(field, invitation, f"Missing required field: {field}")
        
        # Validate field types
        self.assertIsInstance(invitation["id"], int, "ID should be an integer")
        self.assertIsInstance(invitation["email"], str, "Email should be a string")
        self.assertIsInstance(invitation["role"], str, "Role should be a string")
        self.assertIsInstance(invitation["token"], str, "Token should be a string")
        self.assertIsInstance(invitation["created_at"], str, "Created_at should be a string")
        self.assertIsInstance(invitation["expires_at"], str, "Expires_at should be a string")
        self.assertIsInstance(invitation["used"], bool, "Used should be a boolean")
        
        # Validate field values
        self.assertEqual(invitation["email"], self.dummy_email, "Email mismatch")
        self.assertEqual(invitation["role"], "user", "Role should be 'user'")
        self.assertFalse(invitation["used"], "Invitation should not be used")
        
        
        
       

    # def test_register(self):
    #     # Test successful registration
        
    #     payload = {
    #         "username": self.dummy_username,
    #         "password": self.dummy_password,
    #         # "email": self.dummy_email
    #         "invitation_token": invitation_token
    #     }
    #     headers = {
    #         "Content-Type": "application/json",
    #         "Accept": "application/json",
    #         "User-Agent": "test-client"
    #     }

        
    #     response = requests.post(f"{self.base_url}/register", json=payload, headers=headers)

    #     print("Response:", response.status_code, response.text)
    #     self.assertEqual(response.status_code, 200, "Expected status code 200 Created")

if __name__ == "__main__":
    unittest.main()