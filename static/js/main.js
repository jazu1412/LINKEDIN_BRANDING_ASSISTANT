document.addEventListener('DOMContentLoaded', function() {
    const resumeForm = document.getElementById('resumeForm');
    const progressBar = document.querySelector('.progress-bar');
    const loadingDiv = document.querySelector('.loading');

    // Default placeholder messages for empty sections
    const placeholders = {
        about: "No professional summary available",
        experience: "No work experience listed",
        education: "No education details available",
        projects: "No projects listed",
        certifications: "No certifications listed",
        skills: "No skills listed",
        awards: "No awards or honors listed",
        recommendations: "No recommendations available"
    };

    resumeForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const fileInput = document.getElementById('resumeFile');
        const file = fileInput.files[0];
        
        if (!file) {
            alert('Please select a resume file (PDF or TXT)');
            return;
        }

        // Show loading state
        loadingDiv.style.display = 'block';
        setProgressBar(30, 'Analyzing resume...');
        
        const formData = new FormData();
        formData.append('resume', file);

        try {
            const response = await fetch('/upload_resume_for_linkedIn_profile', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            setProgressBar(60, 'Processing data...');

            const data = await response.json();
            
            // Update the profile with the parsed data
            updateProfile(data);
            setProgressBar(data.profile_strength || 100, `Profile ${Math.round(data.profile_strength || 100)}% complete`);

        } catch (error) {
            console.error('Error:', error);
            alert('Error processing resume: ' + error.message);
            setProgressBar(0, 'Error processing resume');
        } finally {
            loadingDiv.style.display = 'none';
        }
    });

    function setProgressBar(percentage, message) {
        progressBar.style.width = `${percentage}%`;
        progressBar.setAttribute('aria-valuenow', percentage);
        
        const statusText = document.querySelector('.card small.text-muted');
        if (statusText) {
            statusText.textContent = message;
        }
    }

    function updateProfile(data) {
        // Update profile header with fallbacks
        if (data.profile_picture) {
            document.querySelectorAll('.profile-photo').forEach(img => {
                img.src = data.profile_picture;
            });
        }
        
        updateTextContent('profileName', data.name || 'Name not provided');
        updateTextContent('profileHeadline', data.headline || 'Professional headline not available');
        
        const profileLocation = document.getElementById('profileLocation');
        if (profileLocation) {
            profileLocation.innerHTML = data.location ? 
                `<i class="fas fa-map-marker-alt me-1"></i>${data.location}` :
                `<i class="fas fa-map-marker-alt me-1"></i>Location not specified`;
        }

        // Update About section with fallback
        updateSection('aboutSection', data.about || placeholders.about);

        // Update Experience section
        if (data.experience && data.experience.length > 0) {
            const experienceHTML = data.experience.map(exp => `
                <div class="experience-item">
                    <h5 class="mb-1">${exp.title || 'Role not specified'}</h5>
                    <p class="text-muted mb-2">${exp.company || 'Company not specified'} ${exp.duration ? `• ${exp.duration}` : ''}</p>
                    <p class="mb-0">${exp.description || 'No description available'}</p>
                </div>
            `).join('');
            updateSection('experienceSection', experienceHTML);
        } else {
            updateSection('experienceSection', `<div class="placeholder-content text-muted">${placeholders.experience}</div>`);
        }

        // Update Education section
        if (data.education && data.education.length > 0) {
            const educationHTML = data.education.map(edu => `
                <div class="education-item">
                    <h5 class="mb-1">${edu.degree || 'Degree not specified'}</h5>
                    <p class="text-muted mb-2">${edu.school || 'Institution not specified'} ${edu.duration ? `• ${edu.duration}` : ''}</p>
                    ${edu.description ? `<p class="mb-0">${edu.description}</p>` : ''}
                </div>
            `).join('');
            updateSection('educationSection', educationHTML);
        } else {
            updateSection('educationSection', `<div class="placeholder-content text-muted">${placeholders.education}</div>`);
        }

        // Update Projects section
        if (data.projects && data.projects.length > 0) {
            const projectsHTML = data.projects.map(project => `
                <div class="project-item">
                    <h5 class="mb-1">${project.name || 'Project name not specified'}</h5>
                    ${project.duration ? `<p class="text-muted mb-2">${project.duration}</p>` : ''}
                    <p class="mb-2">${project.description || 'No description available'}</p>
                    ${project.technologies ? `<p class="mb-0"><strong>Technologies:</strong> ${project.technologies}</p>` : ''}
                </div>
            `).join('');
            updateSection('projectsSection', projectsHTML);
        } else {
            updateSection('projectsSection', `<div class="placeholder-content text-muted">${placeholders.projects}</div>`);
        }

        // Update Certifications section
        if (data.certifications && data.certifications.length > 0) {
            const certificationsHTML = data.certifications.map(cert => `
                <div class="certification-item">
                    <h5 class="mb-1">${cert.name || 'Certification name not specified'}</h5>
                    <p class="text-muted mb-2">${cert.issuer || 'Issuer not specified'} ${cert.date ? `• ${cert.date}` : ''}</p>
                    ${cert.description ? `<p class="mb-0">${cert.description}</p>` : ''}
                </div>
            `).join('');
            updateSection('certificationsSection', certificationsHTML);
        } else {
            updateSection('certificationsSection', `<div class="placeholder-content text-muted">${placeholders.certifications}</div>`);
        }

        // Update Skills section
        if (data.skills && data.skills.length > 0) {
            const skillsHTML = data.skills.map(skill => 
                // `<span class="badge">${skill}</span>`
                `<span class="badge skill-badge bg-light text-dark">${skill}</span>`
            ).join('');
            updateSection('skillsSection', skillsHTML);
        } else {
            updateSection('skillsSection', `<div class="placeholder-content text-muted">${placeholders.skills}</div>`);
        }

        // Update Awards section
        if (data.awards && data.awards.length > 0) {
            const awardsHTML = data.awards.map(award => `
                <div class="award-item">
                    <h5 class="mb-1">${award.name || 'Award name not specified'}</h5>
                    <p class="text-muted mb-2">${award.issuer || 'Issuer not specified'} ${award.date ? `• ${award.date}` : ''}</p>
                    ${award.description ? `<p class="mb-0">${award.description}</p>` : ''}
                </div>
            `).join('');
            updateSection('awardsSection', awardsHTML);
        } else {
            updateSection('awardsSection', `<div class="placeholder-content text-muted">${placeholders.awards}</div>`);
        }

        // Update Recommendations section
        if (data.recommendations && data.recommendations.length > 0) {
            const recommendationsHTML = data.recommendations.map(rec => `
                <div class="recommendation-item">
                    <div class="d-flex align-items-center mb-2">
                        <img src="https://via.placeholder.com/48" class="rounded-circle me-2" alt="Recommender">
                        <div>
                            <h6 class="mb-0">${rec.recommender || 'Professional Recommendation'}</h6>
                            <small class="text-muted">Based on Professional Experience</small>
                        </div>
                    </div>
                    <p class="mb-0">${rec.text || 'No recommendation text available'}</p>
                </div>
            `).join('');
            updateSection('recommendationsSection', recommendationsHTML);
        } else {
            updateSection('recommendationsSection', `<div class="placeholder-content text-muted">${placeholders.recommendations}</div>`);
        }
    }

    function updateSection(sectionId, content) {
        const section = document.getElementById(sectionId);
        if (section) {
            section.innerHTML = content;
        }
    }

    function updateTextContent(elementId, content) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = content;
        }
    }
});
