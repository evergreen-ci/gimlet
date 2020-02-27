package gimlet

// func TestMultiUserManager(t *testing.T) {
//     for testName, testCase := range map[string]func(ctx context.Context, t *testing.T, um gimlet.UserManager, readWrite *MockUserManager, readOnly *MockUserManager){
//         "GetUserByToken": func(ctx context.Context, t *testing.T, um gimlet.UserManager, readWrite *MockUserManager, readOnly *MockUserManager) {
//
//         },
//         // "": func(ctx context.Context, t *testing.T, um gimlet.UserManager, readWrite *MockUserManager, readOnly *MockUserManager){},
//         // "": func(ctx context.Context, t *testing.T, um gimlet.UserManager, readWrite *MockUserManager, readOnly *MockUserManager){},
//         // "": func(ctx context.Context, t *testing.T, um gimlet.UserManager, readWrite *MockUserManager, readOnly *MockUserManager){},
//         // "": func(ctx context.Context, t *testing.T, um gimlet.UserManager, readWrite *MockUserManager, readOnly *MockUserManager){},
//     } {
//         t.Run(testName, func(t *testing.T) {
//             ctx, cancel := context.WithCancel(context.Background())
//             defer cancel()
//             readWrite := &MockUserManager{
//                 // TokenToUsers: map[string]User{
//                 //     ""
//                 // }
//             }
//             readOnly := &MockUserManager{}
//             um := NewMultiUserManager([]UserManager{}, []UserManager{})
//             testCase(ctx, t, um, readWrite, readOnly)
//         })
//     }
// }
