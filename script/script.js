
const pages = document.querySelectorAll(".page");
const links = document.querySelectorAll(".nav-link");

function showPage(pageId) {
    pages.forEach(page => {
        page.classList.remove("active");
    });

    links.forEach(link => {
        link.classList.remove("active");
    });

    const selectedPage = document.getElementById(pageId);

    if (selectedPage) {
        selectedPage.classList.add("active");
    }

    const selectedLink = document.querySelector(
        `[data-page="${pageId}"]`
    );

    if (selectedLink) {
        selectedLink.classList.add("active");
    }

    document.getElementById("sidebar").classList.remove("open");
}

links.forEach(link => {
    link.addEventListener("click", function(event) {
        event.preventDefault();
        showPage(this.dataset.page);
    });
});

// MOBILE MENU

document.getElementById("menuBtn").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("open");
});

// TOAST MESSAGE

function notify(message) {
    const toast = document.getElementById("toast");

    toast.textContent = message;
    toast.classList.add("show");

    setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
}

// EVENT REGISTRATION INTEREST

let events = JSON.parse(
    localStorage.getItem("campusEvents") || "[]"
);

function saveEvent(eventName) {
    if (!events.includes(eventName)) {
        events.push(eventName);
        localStorage.setItem(
            "campusEvents",
            JSON.stringify(events)
        );
        notify("Event added to your interests!");
    } else {
        notify("You have already saved this event.");
    }

    displayEvents();
}

function displayEvents() {
    const list = document.getElementById("savedEvents");

    list.innerHTML = "";

    events.forEach(event => {
        const item = document.createElement("li");
        item.textContent = event;
        list.appendChild(item);
    });
}

displayEvents();

// STUDENT PROFILE

document.getElementById("profileForm")
.addEventListener("submit", function(event) {
    event.preventDefault();

    const student = {
        name: document.getElementById("studentName").value,
        course: document.getElementById("studentCourse").value,
        year: document.getElementById("studentYear").value
    };

    localStorage.setItem(
        "studentProfile",
        JSON.stringify(student)
    );

    notify("Student profile saved successfully!");
});

function loadProfile() {
    const student = JSON.parse(
        localStorage.getItem("studentProfile") || "null"
    );

    if (student) {
        document.getElementById("studentName").value =
            student.name;

        document.getElementById("studentCourse").value =
            student.course;

        document.getElementById("studentYear").value =
            student.year;
    }
}

loadProfile();

// LOST AND FOUND

let lostItems = JSON.parse(
    localStorage.getItem("lostItems") || "[]"
);

const lostForm = document.getElementById("lostForm");

lostForm.addEventListener("submit", function(event) {
    event.preventDefault();

    const item = {
        name: document.getElementById("itemName").value,
        location: document.getElementById("itemLocation").value,
        contact: document.getElementById("itemContact").value
    };

    lostItems.push(item);

    localStorage.setItem(
        "lostItems",
        JSON.stringify(lostItems)
    );

    displayLostItems();

    lostForm.reset();

    notify("Your notice has been posted!");
});

function displayLostItems() {
    const container = document.getElementById("lostItems");

    container.innerHTML = "<h3>Recent notices</h3>";

    lostItems.forEach(item => {
        const card = document.createElement("div");
        const title = document.createElement("h4");
        const location = document.createElement("p");
        const contact = document.createElement("p");

        title.textContent = item.name;
        location.textContent = "Location: " + item.location;
        contact.textContent = "Contact: " + item.contact;

        card.append(title, location, contact);
        container.appendChild(card);
    });
}

displayLostItems();

// SEARCH CAMPUS

document.getElementById("searchInput")
.addEventListener("keydown", function(event) {

    if (event.key === "Enter") {
        const query = this.value.toLowerCase();

        const matchedPage = [
            "announcements",
            "timetable",
            "events",
            "resources",
            "lost",
            "profile"
        ].find(id => {
            return document.getElementById(id)
                .textContent.toLowerCase().includes(query);
        });

        if (matchedPage) {
            showPage(matchedPage);
        } else {
            notify("No matching campus section found.");
        }
    }
});

// NOTIFICATIONS

document.getElementById("notificationBtn")
.addEventListener("click", () => {
    showPage("announcements");
    notify("Check the latest campus announcements.");
});
