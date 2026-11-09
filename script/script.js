
const supabaseConfig = {
    url: "",
    anonKey: ""
};

const pages = document.querySelectorAll(".page");
const links = document.querySelectorAll(".nav-link");
const sidebar = document.getElementById("sidebar");
const menuBtn = document.getElementById("menuBtn");
const toast = document.getElementById("toast");
let toastTimeout;
let supabaseSdkPromise;
let campusSupabaseClient;

function loadSupabaseSdk() {
    if (window.supabase) {
        return Promise.resolve(window.supabase);
    }

    if (!supabaseSdkPromise) {
        supabaseSdkPromise = new Promise((resolve, reject) => {
            const sdk = document.createElement("script");
            sdk.src = "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2";
            sdk.onload = () => {
                if (window.supabase) {
                    resolve(window.supabase);
                } else {
                    reject(new Error("The Supabase client did not initialize."));
                }
            };
            sdk.onerror = () => reject(
                new Error("Could not load the Supabase client.")
            );
            document.head.appendChild(sdk);
        });
    }

    return supabaseSdkPromise;
}

function getSupabaseClient() {
    if (!campusSupabaseClient) {
        campusSupabaseClient =
            window.supabase.createClient(supabaseConfig.url, supabaseConfig.anonKey);
    }

    return campusSupabaseClient;
}

function showPage(pageId) {
    const selectedPage = document.getElementById(pageId);

    if (!selectedPage || !selectedPage.classList.contains("page")) {
        return;
    }

    pages.forEach(page => {
        page.classList.remove("active");
    });

    links.forEach(link => {
        link.classList.remove("active");
        link.removeAttribute("aria-current");
    });

    selectedPage.classList.add("active");

    const selectedLink = document.querySelector(`[data-page="${pageId}"]`);
    if (selectedLink) {
        selectedLink.classList.add("active");
        selectedLink.setAttribute("aria-current", "page");
    }

    closeMenu();
}

links.forEach(link => {
    link.addEventListener("click", event => {
        event.preventDefault();
        showPage(link.dataset.page);
    });
});

function closeMenu() {
    sidebar.classList.remove("open");
    document.getElementById("sidebarBackdrop").classList.remove("open");
    menuBtn.setAttribute("aria-expanded", "false");
}

menuBtn.addEventListener("click", () => {
    const isOpen = sidebar.classList.toggle("open");
    document.getElementById("sidebarBackdrop").classList.toggle("open", isOpen);
    menuBtn.setAttribute("aria-expanded", String(isOpen));
});

document.getElementById("sidebarBackdrop").addEventListener("click", closeMenu);

function notify(message) {
    toast.textContent = message;
    toast.classList.add("show");

    window.clearTimeout(toastTimeout);
    toastTimeout = window.setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
}

let events = JSON.parse(
    localStorage.getItem("campusEvents") || "[]"
);

function saveEvent(eventName) {
    if (events.includes(eventName)) {
        events = events.filter(event => event !== eventName);
        notify("Event removed from your interests.");
    } else {
        events.push(eventName);
        notify("Event added to your interests!");
    }

    localStorage.setItem("campusEvents", JSON.stringify(events));
    displayEvents();
}

function displayEvents() {
    const list = document.getElementById("savedEvents");
    list.replaceChildren();

    if (events.length === 0) {
        const emptyItem = document.createElement("li");
        emptyItem.className = "empty-state";
        emptyItem.textContent = "No event interests saved yet.";
        list.appendChild(emptyItem);
    }

    events.forEach(event => {
        const item = document.createElement("li");
        const name = document.createElement("span");
        const removeButton = document.createElement("button");

        name.textContent = event;
        removeButton.type = "button";
        removeButton.className = "text-button";
        removeButton.dataset.removeEvent = event;
        removeButton.textContent = "Remove";
        item.append(name, removeButton);
        list.appendChild(item);
    });

    document.querySelectorAll("[data-event]").forEach(button => {
        const isSaved = events.includes(button.dataset.event);
        button.textContent = isSaved ? "Remove Interest" : "Register Interest";
        button.setAttribute("aria-pressed", String(isSaved));
    });
}

document.getElementById("savedEvents").addEventListener("click", event => {
    const button = event.target.closest("[data-remove-event]");
    if (button) {
        saveEvent(button.dataset.removeEvent);
    }
});

document.querySelectorAll("[data-event]").forEach(button => {
    button.addEventListener("click", () => saveEvent(button.dataset.event));
});

displayEvents();

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

    updateStudentDisplay(student);
    notify("Student profile saved successfully!");
});

function updateStudentDisplay(student) {
    document.getElementById("welcomeHeading").textContent =
        `Welcome back, ${student.name}!`;

    const initials = student.name
        .trim()
        .split(/\s+/)
        .slice(0, 2)
        .map(name => name[0])
        .join("")
        .toUpperCase();
    document.getElementById("avatar").textContent = initials || "S";
}

function loadProfile() {
    const student = JSON.parse(
        localStorage.getItem("studentProfile") || "null"
    );

    if (student) {
        document.getElementById("studentName").value = student.name || "";
        document.getElementById("studentCourse").value = student.course || "";
        document.getElementById("studentYear").value = student.year || "Year 1";
        updateStudentDisplay(student);
    }
}

loadProfile();

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

    lostItems.unshift(item);
    localStorage.setItem("lostItems", JSON.stringify(lostItems));

    displayLostItems();
    lostForm.reset();
    notify("Your notice has been posted!");
});

function displayLostItems() {
    const container = document.getElementById("lostItems");
    container.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = "Recent notices";
    container.appendChild(heading);

    if (lostItems.length === 0) {
        const emptyMessage = document.createElement("p");
        emptyMessage.className = "empty-state";
        emptyMessage.textContent = "No notices yet. Post one to get started.";
        container.appendChild(emptyMessage);
        return;
    }

    lostItems.forEach((item, index) => {
        const card = document.createElement("article");
        const title = document.createElement("h4");
        const location = document.createElement("p");
        const contact = document.createElement("p");
        const removeButton = document.createElement("button");

        title.textContent = item.name;
        location.textContent = "Location: " + item.location;
        contact.textContent = "Contact: " + item.contact;
        removeButton.type = "button";
        removeButton.className = "text-button";
        removeButton.dataset.removeNotice = String(index);
        removeButton.textContent = "Remove notice";

        card.className = "lost-item";
        card.append(title, location, contact, removeButton);
        container.appendChild(card);
    });
}

document.getElementById("lostItems").addEventListener("click", event => {
    const button = event.target.closest("[data-remove-notice]");
    if (!button) {
        return;
    }

    lostItems.splice(Number(button.dataset.removeNotice), 1);
    localStorage.setItem("lostItems", JSON.stringify(lostItems));
    displayLostItems();
    notify("Notice removed.");
});

displayLostItems();

document.getElementById("searchInput")
.addEventListener("keydown", function(event) {
    if (event.key !== "Enter") {
        return;
    }

    event.preventDefault();
    const query = this.value.trim().toLowerCase();
    if (!query) {
        notify("Enter a search term to find a campus section.");
        return;
    }

    const matchedPage = Array.from(pages)
        .filter(page => page.id !== "dashboard")
        .find(page =>
        page.textContent.toLowerCase().includes(query)
    ) || Array.from(pages).find(page =>
        page.id === "dashboard" &&
        page.textContent.toLowerCase().includes(query)
    );

    if (matchedPage) {
        showPage(matchedPage.id);
        this.blur();
    } else {
        notify("No matching campus section found.");
    }
});

document.getElementById("notificationBtn")
.addEventListener("click", () => {
    showPage("announcements");
    notify("Check the latest campus announcements.");
});

document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
        closeMenu();
    }
});

document.getElementById("dateDisplay").textContent =
    new Intl.DateTimeFormat(undefined, {
        day: "numeric",
        month: "long",
        year: "numeric"
    }).format(new Date());

function initializeLecturerDashboard() {
    const setupPanel = document.getElementById("lecturerSetup");
    const authPanel = document.getElementById("lecturerAuth");
    const workspace = document.getElementById("lecturerWorkspace");
    const status = document.getElementById("lecturerAuthStatus");
    const classAnnouncementStatus =
        document.getElementById("classAnnouncementStatus");
    const sharedAssignmentStatus =
        document.getElementById("sharedAssignmentStatus");
    const pendingSignOutButton =
        document.getElementById("lecturerPendingSignOutButton");
    const config = supabaseConfig;
    let currentUser = null;

    function setStatus(message, isError = false) {
        status.textContent = message;
        status.classList.toggle("error", isError);
    }

    function renderAnnouncements(announcements, container) {
        container.replaceChildren();

        if (announcements.length === 0) {
            const emptyMessage = document.createElement("p");
            emptyMessage.className = "empty-state";
            emptyMessage.textContent = "No class announcements posted yet.";
            container.appendChild(emptyMessage);
            return;
        }

        announcements.forEach(announcement => {
            const card = document.createElement("article");
            const title = document.createElement("h3");
            const details = document.createElement("p");
            const message = document.createElement("p");

            card.className = "class-announcement";
            title.textContent = announcement.title;
            details.className = "class-announcement-details";
            details.textContent =
                `${announcement.course} · ${new Date(announcement.created_at).toLocaleString()}`;
            message.textContent = announcement.message;
            card.append(title, details, message);
            container.appendChild(card);
        });
    }

    async function loadClassAnnouncements(client) {
        classAnnouncementStatus.textContent = "Loading class announcements...";
        const { data, error } = await client
            .from("class_announcements")
            .select("id, lecturer_id, course, title, message, created_at")
            .order("created_at", { ascending: false })
            .limit(50);

        if (error) {
            classAnnouncementStatus.textContent =
                `Could not load class announcements: ${error.message}`;
            return;
        }

        classAnnouncementStatus.textContent = "";
        renderAnnouncements(data || [], document.getElementById("classAnnouncementList"));
        document.getElementById("classAnnouncementCount").textContent =
            String((data || []).length);
        renderAnnouncements(
            data || [],
            document.getElementById("lecturerAnnouncementList")
        );
    }

    async function downloadAssignment(client, assignment) {
        const { data, error } = await client.storage
            .from("assignments")
            .download(assignment.file_path);

        if (error) {
            throw new Error(error.message);
        }

        const downloadUrl = URL.createObjectURL(data);
        const link = document.createElement("a");
        link.href = downloadUrl;
        link.download = assignment.file_name;
        link.click();
        window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
    }

    function renderAssignments(client, assignments, container) {
        container.replaceChildren();
        if (assignments.length === 0) {
            const emptyMessage = document.createElement("p");
            emptyMessage.className = "empty-state";
            emptyMessage.textContent = "No assignments have been uploaded yet.";
            container.appendChild(emptyMessage);
            return;
        }

        assignments.forEach(assignment => {
            const card = document.createElement("article");
            const title = document.createElement("h4");
            const details = document.createElement("p");
            const downloadButton = document.createElement("button");

            card.className = "lecturer-item";
            title.textContent = assignment.title;
            details.textContent = `${assignment.course} · ${assignment.file_name}` +
                (assignment.due_date
                    ? ` · Due ${new Date(`${assignment.due_date}T00:00:00`).toLocaleDateString()}`
                    : "");
            downloadButton.type = "button";
            downloadButton.className = "text-button";
            downloadButton.textContent = "Download";
            downloadButton.addEventListener("click", async () => {
                downloadButton.disabled = true;
                try {
                    await downloadAssignment(client, assignment);
                } catch (error) {
                    setStatus(`Could not download assignment: ${error.message}`, true);
                } finally {
                    downloadButton.disabled = false;
                }
            });
            card.append(title, details, downloadButton);
            container.appendChild(card);
        });
    }

    async function loadAssignments(client, isLecturer) {
        const sharedList = document.getElementById("sharedAssignmentList");
        if (!isLecturer) {
            sharedList.replaceChildren();
            sharedAssignmentStatus.textContent =
                "Sign in through Messaging to view and download class assignments.";
            return;
        }

        sharedAssignmentStatus.textContent = "Loading assignments...";
        const { data, error } = await client
            .from("course_assignments")
            .select("id, lecturer_id, course, title, due_date, file_path, file_name, created_at")
            .order("created_at", { ascending: false })
            .limit(100);

        if (error) {
            sharedAssignmentStatus.textContent =
                `Could not load assignments: ${error.message}`;
            setStatus(`Could not load assignments: ${error.message}`, true);
            return;
        }

        const assignments = data || [];
        document.getElementById("assignmentCount").textContent =
            String(assignments.length);
        sharedAssignmentStatus.textContent = "";
        renderAssignments(
            client,
            assignments,
            document.getElementById("assignmentList")
        );
        renderAssignments(client, assignments, sharedList);
    }

    function showAuthMode(mode) {
        const isSignup = mode === "signup";
        const nameField = document.getElementById("lecturerNameField");
        document.getElementById("lecturerAuthHeading").textContent =
            isSignup ? "Lecturer registration" : "Lecturer sign in";
        document.getElementById("lecturerAuthSubmit").textContent =
            isSignup ? "Submit registration" : "Sign in";
        document.getElementById("lecturerAuthModeToggle").textContent =
            isSignup ? "Already registered? Sign in" : "Register as a lecturer";
        nameField.hidden = !isSignup;
        nameField.querySelector("input").required = isSignup;
        document.getElementById("lecturerPassword").autocomplete =
            isSignup ? "new-password" : "current-password";
        document.getElementById("lecturerAuthForm").dataset.mode = mode;
    }

    async function loadUser(client, user) {
        setStatus("Checking lecturer account...");
        const { data: profile, error } = await client
            .from("profiles")
            .select("id, full_name, role")
            .eq("id", user.id)
            .single();

        if (!currentUser || currentUser.id !== user.id) {
            return;
        }
        if (error) {
            setStatus(`Could not load your account: ${error.message}`, true);
            return;
        }

        if (profile.role !== "lecturer") {
            const { data: application, error: applicationError } = await client
                .from("lecturer_applications")
                .select("status")
                .eq("user_id", user.id)
                .maybeSingle();

            if (!currentUser || currentUser.id !== user.id) {
                return;
            }
            if (applicationError) {
                setStatus(
                    `Could not check lecturer registration: ${applicationError.message}`,
                    true
                );
                return;
            }

            workspace.hidden = true;
            authPanel.hidden = true;
            pendingSignOutButton.hidden = false;
            if (application?.status === "rejected") {
                setStatus("Your lecturer registration was not approved. Contact your campus administrator.");
            } else if (application) {
                setStatus("Your lecturer registration is awaiting administrator approval.");
            } else {
                setStatus("This account does not have lecturer access. Register as a lecturer or sign in with an approved account.");
            }
            await loadAssignments(client, true);
            return;
        }

        authPanel.hidden = true;
        pendingSignOutButton.hidden = true;
        setupPanel.hidden = true;
        workspace.hidden = false;
        document.getElementById("lecturerAccountLabel").textContent =
            `${profile.full_name} · Lecturer`;
        setStatus(`Signed in as ${profile.full_name}.`);
        await Promise.all([
            loadAssignments(client, true),
            loadClassAnnouncements(client)
        ]);
    }

    function showSignedOut(message = "Sign in with your lecturer account to continue.") {
        currentUser = null;
        workspace.hidden = true;
        authPanel.hidden = false;
        pendingSignOutButton.hidden = true;
        showAuthMode("signin");
        setStatus(message);
    }

    if (!config.url || !config.anonKey) {
        setupPanel.hidden = false;
        authPanel.hidden = true;
        setStatus("Lecturer services are not connected to a Supabase project.");
        classAnnouncementStatus.textContent =
            "Connect Supabase to load class announcements.";
        sharedAssignmentStatus.textContent =
            "Connect Supabase to load class assignments.";
        return;
    }

    setStatus("Loading lecturer services...");
    loadSupabaseSdk().then(() => {
        const client = getSupabaseClient();
        const authForm = document.getElementById("lecturerAuthForm");
        const modeToggle = document.getElementById("lecturerAuthModeToggle");
        const nameInput = document.getElementById("lecturerName");
        let authRequestPending = false;

        setupPanel.hidden = true;
        showAuthMode("signin");
        loadClassAnnouncements(client);

        modeToggle.addEventListener("click", () => {
            const isSignup = authForm.dataset.mode === "signup";
            showAuthMode(isSignup ? "signin" : "signup");
            setStatus("");
        });

        authForm.addEventListener("submit", async event => {
            event.preventDefault();
            if (authRequestPending) {
                return;
            }

            const mode = authForm.dataset.mode;
            const email = document.getElementById("lecturerEmail").value.trim();
            const password = document.getElementById("lecturerPassword").value;
            const submitButton = document.getElementById("lecturerAuthSubmit");
            authRequestPending = true;
            submitButton.disabled = true;
            setStatus(mode === "signup"
                ? "Submitting lecturer registration..."
                : "Signing in...");

            const result = mode === "signup"
                ? await client.auth.signUp({
                    email,
                    password,
                    options: {
                        data: {
                            full_name: nameInput.value.trim(),
                            registration_type: "lecturer"
                        }
                    }
                })
                : await client.auth.signInWithPassword({ email, password });

            authRequestPending = false;
            submitButton.disabled = false;
            if (result.error) {
                setStatus(`Authentication failed: ${result.error.message}`, true);
                return;
            }

            if (mode === "signup" && !result.data.session) {
                showAuthMode("signin");
                setStatus("Registration submitted. Confirm your email, then sign in. Lecturer access remains pending until an administrator approves it.");
            } else if (result.data.user) {
                currentUser = result.data.user;
                await loadUser(client, result.data.user);
            }
        });

        async function signOut() {
            const { error } = await client.auth.signOut();
            if (error) {
                setStatus(`Could not sign out: ${error.message}`, true);
            }
        }

        document.getElementById("lecturerSignOutButton")
            .addEventListener("click", signOut);
        pendingSignOutButton.addEventListener("click", signOut);
        document.getElementById("classAnnouncementForm")
            .addEventListener("submit", async event => {
                event.preventDefault();
                if (!currentUser) {
                    setStatus("Sign in with an approved lecturer account to post.", true);
                    return;
                }

                const announcement = {
                    lecturer_id: currentUser.id,
                    course: document.getElementById("announcementClass").value.trim(),
                    title: document.getElementById("classAnnouncementTitle").value.trim(),
                    message: document.getElementById("classAnnouncementMessage").value.trim()
                };
                const submitButton = event.currentTarget.querySelector(
                    'button[type="submit"]'
                );
                submitButton.disabled = true;
                const { error } = await client
                    .from("class_announcements")
                    .insert(announcement);
                submitButton.disabled = false;

                if (error) {
                    setStatus(`Could not post announcement: ${error.message}`, true);
                    return;
                }

                event.currentTarget.reset();
                setStatus("Class announcement posted.");
                await loadClassAnnouncements(client);
            });

        document.getElementById("assignmentForm")
            .addEventListener("submit", async event => {
                event.preventDefault();
                const file = document.getElementById("assignmentFile").files[0];
                if (!file || !currentUser) {
                    setStatus("Sign in with an approved lecturer account and choose an assignment file.", true);
                    return;
                }
                if (file.size > 10 * 1024 * 1024) {
                    setStatus("Assignment files must be 10 MB or smaller.", true);
                    return;
                }

                const form = event.currentTarget;
                const submitButton = form.querySelector('button[type="submit"]');
                const assignmentId = window.crypto.randomUUID
                    ? window.crypto.randomUUID()
                    : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
                const filePath = `${currentUser.id}/${assignmentId}`;
                const assignment = {
                    lecturer_id: currentUser.id,
                    course: document.getElementById("assignmentClass").value.trim(),
                    title: document.getElementById("assignmentTitle").value.trim(),
                    due_date: document.getElementById("assignmentDueDate").value || null,
                    file_path: filePath,
                    file_name: file.name
                };

                submitButton.disabled = true;
                const { error: uploadError } = await client.storage
                    .from("assignments")
                    .upload(filePath, file, {
                        contentType: file.type || "application/octet-stream",
                        upsert: false
                    });
                if (uploadError) {
                    submitButton.disabled = false;
                    setStatus(`Could not upload assignment file: ${uploadError.message}`, true);
                    return;
                }

                const { error: recordError } = await client
                    .from("course_assignments")
                    .insert(assignment);
                if (recordError) {
                    const { error: cleanupError } = await client.storage
                        .from("assignments")
                        .remove([filePath]);
                    submitButton.disabled = false;
                    const cleanupMessage = cleanupError
                        ? ` The uploaded file also could not be removed: ${cleanupError.message}`
                        : "";
                    setStatus(
                        `Could not save assignment details: ${recordError.message}.${cleanupMessage}`,
                        true
                    );
                    return;
                }

                submitButton.disabled = false;
                form.reset();
                setStatus("Assignment uploaded successfully.");
                await loadAssignments(client, true);
            });

        client.auth.onAuthStateChange((_event, session) => {
            window.setTimeout(() => {
                if (session?.user) {
                    currentUser = session.user;
                    loadUser(client, session.user);
                } else {
                    showSignedOut();
                    sharedAssignmentStatus.textContent =
                        "Sign in through Messaging to view and download class assignments.";
                    document.getElementById("sharedAssignmentList").replaceChildren();
                }
            }, 0);
        });

        client.auth.getSession().then(({ data, error }) => {
            if (error) {
                setStatus(`Could not restore your lecturer session: ${error.message}`, true);
                showSignedOut("Could not restore your session. Please sign in again.");
            } else if (data.session?.user) {
                currentUser = data.session.user;
                loadUser(client, data.session.user);
            } else {
                showSignedOut();
                sharedAssignmentStatus.textContent =
                    "Sign in through Messaging to view and download class assignments.";
            }
        });
    }).catch(error => {
        setupPanel.hidden = false;
        setStatus(`${error.message} Check your internet connection.`, true);
        classAnnouncementStatus.textContent =
            "Could not connect to the class announcement service.";
    });
}

function initializeMessaging() {
    const setupPanel = document.getElementById("messagingSetup");
    const authPanel = document.getElementById("messagingAuth");
    const workspace = document.getElementById("messagingWorkspace");
    const status = document.getElementById("messagingStatus");
    const config = supabaseConfig;

    function setStatus(message, isError = false) {
        status.textContent = message;
        status.classList.toggle("error", isError);
    }

    if (!config.url || !config.anonKey) {
        setupPanel.hidden = false;
        setStatus("Messaging is not connected to a Supabase project.");
        return;
    }

    if (!window.supabase) {
        setStatus("Loading the messaging service...");
        loadSupabaseSdk().then(initializeMessaging).catch(error => {
            setupPanel.hidden = false;
            setStatus(`${error.message} Check your internet connection.`, true);
        });
        return;
    }

    const client = getSupabaseClient();
    const authForm = document.getElementById("authForm");
    const authModeToggle = document.getElementById("authModeToggle");
    const signupName = document.getElementById("signupName");
    const conversationList = document.getElementById("conversationList");
    const messageList = document.getElementById("messageList");
    const messageForm = document.getElementById("messageForm");
    const messageInput = document.getElementById("messageInput");
    let authMode = "signin";
    let currentUser = null;
    let currentProfile = null;
    let activeConversationId = null;
    let activeChannel = null;
    let renderedMessageIds = new Set();
    let directory = new Map();

    function showSignedOut() {
        currentUser = null;
        currentProfile = null;
        activeConversationId = null;
        directory = new Map();
        if (activeChannel) {
            client.removeChannel(activeChannel);
            activeChannel = null;
        }
        workspace.hidden = true;
        setupPanel.hidden = true;
        authPanel.hidden = false;
        setStatus("Sign in with your campus account to access messaging.");
    }

    function showAuthMode() {
        const isSignup = authMode === "signup";
        document.getElementById("authHeading").textContent =
            isSignup ? "Create a messaging account" : "Sign in to messaging";
        document.getElementById("authSubmit").textContent =
            isSignup ? "Create account" : "Sign in";
        authModeToggle.textContent =
            isSignup ? "Already have an account? Sign in" : "Create an account";
        signupName.parentElement.hidden = !isSignup;
        signupName.required = isSignup;
        document.getElementById("authPassword").autocomplete =
            isSignup ? "new-password" : "current-password";
    }

    async function loadDirectory() {
        const recipientSelect = document.getElementById("recipientSelect");
        const oppositeRole = currentProfile.role === "student"
            ? "lecturer"
            : "student";
        const { data, error } = await client
            .from("profiles")
            .select("id, full_name, role")
            .eq("role", oppositeRole)
            .order("full_name");

        if (error) {
            setStatus(`Could not load the campus directory: ${error.message}`, true);
            return;
        }

        directory = new Map((data || []).map(profile => [profile.id, profile]));
        recipientSelect.replaceChildren();
        const placeholder = document.createElement("option");
        placeholder.value = "";
        placeholder.textContent = data.length
            ? "Choose a recipient"
            : `No ${oppositeRole}s are available yet`;
        recipientSelect.appendChild(placeholder);

        data.forEach(profile => {
            const option = document.createElement("option");
            option.value = profile.id;
            option.textContent = profile.full_name;
            recipientSelect.appendChild(option);
        });
    }

    function appendMessage(message) {
        if (renderedMessageIds.has(message.id)) {
            return;
        }

        renderedMessageIds.add(message.id);
        const bubble = document.createElement("article");
        const body = document.createElement("p");
        const metadata = document.createElement("small");
        const senderName = message.sender_id === currentUser.id
            ? "You"
            : directory.get(message.sender_id)?.full_name || "Campus member";

        bubble.className = "message-bubble";
        if (message.sender_id === currentUser.id) {
            bubble.classList.add("own");
        }
        body.textContent = message.body;
        metadata.textContent =
            `${senderName} · ${new Date(message.created_at).toLocaleString()}`;
        bubble.append(body, metadata);
        messageList.appendChild(bubble);
        messageList.scrollTop = messageList.scrollHeight;
    }

    async function openConversation(conversation) {
        activeConversationId = conversation.id;
        document.getElementById("threadPrompt").hidden = true;
        messageForm.hidden = false;
        messageList.replaceChildren();
        renderedMessageIds = new Set();

        conversationList.querySelectorAll(".conversation-button").forEach(button => {
            button.setAttribute(
                "aria-current",
                String(button.dataset.conversationId === conversation.id)
            );
        });

        if (activeChannel) {
            client.removeChannel(activeChannel);
            activeChannel = null;
        }

        const { data, error } = await client
            .from("messages")
            .select("id, sender_id, body, created_at")
            .eq("conversation_id", conversation.id)
            .order("created_at", { ascending: true })
            .limit(100);

        if (activeConversationId !== conversation.id) {
            return;
        }
        if (error) {
            setStatus(`Could not load messages: ${error.message}`, true);
            return;
        }

        (data || []).forEach(appendMessage);
        activeChannel = client
            .channel(`conversation:${conversation.id}`)
            .on("postgres_changes", {
                event: "INSERT",
                schema: "public",
                table: "messages",
                filter: `conversation_id=eq.${conversation.id}`
            }, payload => appendMessage(payload.new))
            .subscribe(channelStatus => {
                if (channelStatus === "CHANNEL_ERROR" ||
                    channelStatus === "TIMED_OUT") {
                    setStatus("Live updates are unavailable. Check your Supabase Realtime setup.", true);
                }
            });
        messageInput.focus();
    }

    async function loadConversations() {
        const { data, error } = await client
            .from("conversations")
            .select("id, student_id, lecturer_id, created_at")
            .or(`student_id.eq.${currentUser.id},lecturer_id.eq.${currentUser.id}`)
            .order("created_at", { ascending: false });

        if (error) {
            setStatus(`Could not load conversations: ${error.message}`, true);
            return;
        }

        conversationList.replaceChildren();
        if (!data.length) {
            const emptyMessage = document.createElement("p");
            emptyMessage.className = "empty-state";
            emptyMessage.textContent = "Your conversations will appear here.";
            conversationList.appendChild(emptyMessage);
        }

        data.forEach(conversation => {
            const otherId = conversation.student_id === currentUser.id
                ? conversation.lecturer_id
                : conversation.student_id;
            const person = directory.get(otherId);
            const button = document.createElement("button");
            const role = document.createElement("small");

            button.type = "button";
            button.className = "conversation-button";
            button.dataset.conversationId = conversation.id;
            button.textContent = person?.full_name || "Campus member";
            role.textContent = person?.role || "Campus account";
            button.appendChild(role);
            button.addEventListener("click", () => openConversation(conversation));
            conversationList.appendChild(button);
        });

        if (activeConversationId) {
            const active = data.find(item => item.id === activeConversationId);
            if (active) {
                await openConversation(active);
            }
        }
    }

    async function loadUser(user) {
        if (currentUser?.id === user.id) {
            return;
        }

        currentUser = user;
        authPanel.hidden = true;
        setupPanel.hidden = true;
        workspace.hidden = false;
        setStatus("Loading your messaging profile...");

        const { data: profile, error } = await client
            .from("profiles")
            .select("id, full_name, role")
            .eq("id", user.id)
            .single();

        if (error) {
            setStatus(`Could not load your profile: ${error.message}`, true);
            return;
        }

        currentProfile = profile;
        document.getElementById("accountLabel").textContent =
            `${profile.full_name} · ${profile.role}`;
        await loadDirectory();
        await loadConversations();
        if (!status.classList.contains("error")) {
            setStatus(`Signed in as ${profile.role}.`);
        }
    }

    authModeToggle.addEventListener("click", () => {
        authMode = authMode === "signin" ? "signup" : "signin";
        showAuthMode();
        setStatus("");
    });

    authForm.addEventListener("submit", async event => {
        event.preventDefault();
        const email = document.getElementById("authEmail").value.trim();
        const password = document.getElementById("authPassword").value;
        const submitButton = document.getElementById("authSubmit");
        submitButton.disabled = true;
        setStatus(authMode === "signup" ? "Creating your account..." : "Signing in...");

        const result = authMode === "signup"
            ? await client.auth.signUp({
                email,
                password,
                options: { data: { full_name: signupName.value.trim() } }
            })
            : await client.auth.signInWithPassword({ email, password });

        submitButton.disabled = false;
        if (result.error) {
            setStatus(`Authentication failed: ${result.error.message}`, true);
            return;
        }
        if (authMode === "signup" && !result.data.session) {
            setStatus("Account created. Check your email to confirm it, then sign in.");
        } else {
            setStatus("Account ready. Loading your conversations...");
        }
    });

    document.getElementById("signOutButton").addEventListener("click", async () => {
        const { error } = await client.auth.signOut();
        if (error) {
            setStatus(`Could not sign out: ${error.message}`, true);
        }
    });

    document.getElementById("startConversationButton")
        .addEventListener("click", async () => {
            const recipientId = document.getElementById("recipientSelect").value;
            if (!recipientId) {
                setStatus("Choose a student or lecturer first.", true);
                return;
            }

            const studentId = currentProfile.role === "student"
                ? currentUser.id
                : recipientId;
            const lecturerId = currentProfile.role === "lecturer"
                ? currentUser.id
                : recipientId;
            const { data: existing, error: lookupError } = await client
                .from("conversations")
                .select("id, student_id, lecturer_id, created_at")
                .eq("student_id", studentId)
                .eq("lecturer_id", lecturerId)
                .maybeSingle();

            if (lookupError) {
                setStatus(`Could not check conversations: ${lookupError.message}`, true);
                return;
            }

            let conversation = existing;
            if (!conversation) {
                const { data, error } = await client
                    .from("conversations")
                    .insert({ student_id: studentId, lecturer_id: lecturerId })
                    .select("id, student_id, lecturer_id, created_at")
                    .single();
                if (error) {
                    setStatus(`Could not start conversation: ${error.message}`, true);
                    return;
                }
                conversation = data;
            }

            await loadConversations();
            await openConversation(conversation);
        });

    messageForm.addEventListener("submit", async event => {
        event.preventDefault();
        const body = messageInput.value.trim();
        if (!activeConversationId || !body) {
            return;
        }

        const sendButton = messageForm.querySelector("button");
        sendButton.disabled = true;
        const { data, error } = await client
            .from("messages")
            .insert({
                conversation_id: activeConversationId,
                sender_id: currentUser.id,
                body
            })
            .select("id, sender_id, body, created_at")
            .single();
        sendButton.disabled = false;

        if (error) {
            setStatus(`Message could not be sent: ${error.message}`, true);
            return;
        }

        messageInput.value = "";
        appendMessage(data);
    });

    showAuthMode();
    client.auth.onAuthStateChange((_event, session) => {
        window.setTimeout(() => {
            if (session?.user) {
                loadUser(session.user);
            } else {
                showSignedOut();
            }
        }, 0);
    });

    client.auth.getSession().then(({ data, error }) => {
        if (error) {
            setStatus(`Could not restore your session: ${error.message}`, true);
            showSignedOut();
        } else if (data.session?.user) {
            loadUser(data.session.user);
        } else {
            showSignedOut();
        }
    });
}

initializeMessaging();
