import java.util.scanner ;

class StudentRecord {
    // Fields (Attributes)
    String studentID;
    String name;
    String course;

    // Constructor to initialize fields
    public StudentRecord(String studentID, String name, String course) {
        this.studentID = studentID;
        this.name = name;
        this.course = course;
    }

    // Method to display student details
    public void displayInfo() {
        System.out.println("\n--- Student Information ---");
        System.out.println("Student ID: " + studentID);
        System.out.println("Name:       " + name);
        System.out.println("Course:     " + course);
    }
}

public class StudentApp {
    public static void main(String[] args) {
        // Create a Scanner object for user input
        Scanner scanner = new Scanner(System.in);

        // Prompting the user for data
        System.out.print("Enter Student ID: ");
        String id = scanner.nextLine();

        System.out.print("Enter Student Name: ");
        String name = scanner.nextLine();

        System.out.print("Enter Course: ");
        String course = scanner.nextLine();

        // Instantiate the StudentRecord object using the constructor
        StudentRecord student = new StudentRecord(id, name, course);

        // Call the displayInfo method
        student.displayInfo();

        // Close the scanner to prevent memory leaks
        scanner.close();
    }
}